package cache

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"pigcloud/internal/fsutil"
)

const (
	cacheChunkSize = 1024 * 1024

	nonceSize = 24

	fullRecordSize = 4 + nonceSize + cacheChunkSize + chacha20poly1305.Overhead

	chunkCacheMax = 8
)

type chunkKey struct {
	hash string
	idx  int64
}

type Store struct {
	dir string
	cek []byte

	bytes atomic.Int64

	mu sync.Mutex

	chunkMu    sync.Mutex
	chunkCache map[chunkKey][]byte
	chunkOrder []chunkKey
}

var errChunkEOF = errors.New("chunk past end of file")

func NewStore(cacheDir string) (*Store, error) {
	storeDir := filepath.Join(cacheDir, "store")
	if err := os.MkdirAll(storeDir, 0700); err != nil {
		return nil, fmt.Errorf("create store dir: %w", err)
	}

	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("generate CEK: %w", err)
	}

	s := &Store{dir: storeDir, cek: cek}
	s.bytes.Store(s.walkBytes())
	return s, nil
}

func (s *Store) Bytes() int64 {
	n := s.bytes.Load()
	if n >= 0 {
		return n
	}
	return s.ResyncBytes()
}

func (s *Store) ResyncBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := s.walkBytes()
	s.bytes.Store(total)
	return total
}

func (s *Store) walkBytes() int64 {
	var total int64
	shards, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(s.dir, shard.Name()))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || fsutil.IsTempName(e.Name()) {
				continue
			}
			if info, ierr := e.Info(); ierr == nil {
				total += info.Size()
			}
		}
	}
	return total
}

func (s *Store) Close() {
	for i := range s.cek {
		s.cek[i] = 0
	}
}

func (s *Store) Put(data []byte) (string, error) {
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	err := s.putSealed(hash, func(w io.Writer) error {
		_, sealErr := s.sealStream(bytes.NewReader(data), hash, w)
		return sealErr
	})
	if err != nil {
		return "", err
	}
	return hash, nil
}

func (s *Store) putSealed(hash string, seal func(w io.Writer) error) error {
	path := s.pathFor(hash)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(path); err == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create shard dir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), fsutil.TempPattern)
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	if err := seal(tmp); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync cache file: %w", err)
	}
	written := int64(0)
	if fi, statErr := tmp.Stat(); statErr == nil {
		written = fi.Size()
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close cache file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit cache file: %w", err)
	}
	committed = true
	s.bytes.Add(written)
	return nil
}

func (s *Store) sealStream(r io.Reader, hash string, out io.Writer) (int64, error) {
	aead, err := chacha20poly1305.NewX(s.cek)
	if err != nil {
		return 0, fmt.Errorf("create AEAD: %w", err)
	}
	buf := make([]byte, cacheChunkSize)
	lenBuf := make([]byte, 4)
	var total int64
	for {
		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			nonce := make([]byte, nonceSize)
			if _, err := rand.Read(nonce); err != nil {
				return total, fmt.Errorf("generate nonce: %w", err)
			}
			ciphertext := aead.Seal(nil, nonce, buf[:n], chunkAD(uint64(total), hash))
			binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
			if _, err := out.Write(lenBuf); err != nil {
				return total, err
			}
			if _, err := out.Write(nonce); err != nil {
				return total, err
			}
			if _, err := out.Write(ciphertext); err != nil {
				return total, err
			}
			total += int64(n)
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return total, fmt.Errorf("read plaintext: %w", readErr)
		}
	}
	return total, nil
}

func (s *Store) PutFile(srcPath string) (string, error) {
	f, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("open source file: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		f.Close()
		return "", fmt.Errorf("hash source file: %w", err)
	}
	f.Close()
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	err = s.putSealed(hash, func(w io.Writer) error {
		in, openErr := os.Open(srcPath)
		if openErr != nil {
			return fmt.Errorf("reopen source file: %w", openErr)
		}
		defer in.Close()

		verifier := sha256.New()
		if _, sealErr := s.sealStream(io.TeeReader(in, verifier), hash, w); sealErr != nil {
			return sealErr
		}
		if fmt.Sprintf("%x", verifier.Sum(nil)) != hash {
			return fmt.Errorf("source file changed during ingest")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hash, nil
}

func (s *Store) Get(hash string) ([]byte, error) {
	path := s.pathFor(hash)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cache file: %w", err)
	}
	defer f.Close()

	aead, err := chacha20poly1305.NewX(s.cek)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	var result []byte
	offset := uint64(0)
	lenBuf := make([]byte, 4)
	nonceBuf := make([]byte, nonceSize)

	for {
		if _, err := io.ReadFull(f, lenBuf); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("read chunk length: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if _, err := io.ReadFull(f, nonceBuf); err != nil {
			return nil, fmt.Errorf("read nonce: %w", err)
		}

		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(f, ciphertext); err != nil {
			return nil, fmt.Errorf("read ciphertext: %w", err)
		}

		plaintext, err := aead.Open(nil, nonceBuf, ciphertext, chunkAD(offset, hash))
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk at offset %d: %w", offset, err)
		}

		result = append(result, plaintext...)
		offset += uint64(len(plaintext))
	}

	return result, nil
}

func (s *Store) WriteTo(hash string, w io.Writer) (int64, error) {
	path := s.pathFor(hash)
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open cache file: %w", err)
	}
	defer f.Close()

	aead, err := chacha20poly1305.NewX(s.cek)
	if err != nil {
		return 0, fmt.Errorf("create AEAD: %w", err)
	}

	var written int64
	offset := uint64(0)
	lenBuf := make([]byte, 4)
	nonceBuf := make([]byte, nonceSize)

	for {
		if _, err := io.ReadFull(f, lenBuf); err == io.EOF {
			break
		} else if err != nil {
			return written, fmt.Errorf("read chunk length: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if _, err := io.ReadFull(f, nonceBuf); err != nil {
			return written, fmt.Errorf("read nonce: %w", err)
		}

		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(f, ciphertext); err != nil {
			return written, fmt.Errorf("read ciphertext: %w", err)
		}

		plaintext, err := aead.Open(nil, nonceBuf, ciphertext, chunkAD(offset, hash))
		if err != nil {
			return written, fmt.Errorf("decrypt chunk at offset %d: %w", offset, err)
		}

		n, err := w.Write(plaintext)
		written += int64(n)
		if err != nil {
			return written, fmt.Errorf("write chunk at offset %d: %w", offset, err)
		}
		offset += uint64(len(plaintext))
	}

	return written, nil
}

func (s *Store) ReadAt(hash string, off int64, size int) ([]byte, error) {
	if size <= 0 || off < 0 {
		return nil, nil
	}
	rangeEnd := off + int64(size)
	startChunk := off / cacheChunkSize

	var result []byte
	var f *os.File
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	for chunkIdx := startChunk; chunkIdx*cacheChunkSize < rangeEnd; chunkIdx++ {
		chunkStart := chunkIdx * cacheChunkSize

		plain, ok := s.chunkCacheGet(hash, chunkIdx)
		if !ok {
			if f == nil {
				var err error
				f, err = os.Open(s.pathFor(hash))
				if err != nil {
					return nil, fmt.Errorf("open cache file: %w", err)
				}
			}
			var err error
			plain, err = s.readChunkAt(f, chunkIdx, hash)
			if errors.Is(err, errChunkEOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			s.chunkCachePut(hash, chunkIdx, plain)
		}
		if len(plain) == 0 {
			break
		}

		sliceStart := int64(0)
		if off > chunkStart {
			sliceStart = off - chunkStart
		}
		sliceEnd := min(rangeEnd-chunkStart, int64(len(plain)))
		if sliceStart < sliceEnd {
			result = append(result, plain[sliceStart:sliceEnd]...)
		}

		if int64(len(plain)) < cacheChunkSize {
			break
		}
	}

	return result, nil
}

func (s *Store) readChunkAt(f *os.File, chunkIdx int64, hash string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(s.cek)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}
	if _, err := f.Seek(chunkIdx*int64(fullRecordSize), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek chunk %d: %w", chunkIdx, err)
	}

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(f, lenBuf); err == io.EOF {
		return nil, errChunkEOF
	} else if err == io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("truncated chunk %d length prefix", chunkIdx)
	} else if err != nil {
		return nil, fmt.Errorf("read chunk length: %w", err)
	}
	chunkLen := binary.BigEndian.Uint32(lenBuf)

	nonceBuf := make([]byte, nonceSize)
	if _, err := io.ReadFull(f, nonceBuf); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	ciphertext := make([]byte, chunkLen)
	if _, err := io.ReadFull(f, ciphertext); err != nil {
		return nil, fmt.Errorf("read ciphertext: %w", err)
	}

	plain, err := aead.Open(nil, nonceBuf, ciphertext, chunkAD(uint64(chunkIdx*cacheChunkSize), hash))
	if err != nil {
		return nil, fmt.Errorf("decrypt chunk %d: %w", chunkIdx, err)
	}
	return plain, nil
}

func chunkAD(offset uint64, hash string) []byte {
	ad := make([]byte, 8+len(hash))
	binary.BigEndian.PutUint64(ad[:8], offset)
	copy(ad[8:], hash)
	return ad
}

func (s *Store) chunkCacheGet(hash string, idx int64) ([]byte, bool) {
	s.chunkMu.Lock()
	defer s.chunkMu.Unlock()
	p, ok := s.chunkCache[chunkKey{hash, idx}]
	return p, ok
}

func (s *Store) chunkCachePut(hash string, idx int64, plain []byte) {
	s.chunkMu.Lock()
	defer s.chunkMu.Unlock()
	if s.chunkCache == nil {
		s.chunkCache = make(map[chunkKey][]byte)
	}
	k := chunkKey{hash, idx}
	if _, exists := s.chunkCache[k]; !exists {
		s.chunkOrder = append(s.chunkOrder, k)
		for len(s.chunkOrder) > chunkCacheMax {
			delete(s.chunkCache, s.chunkOrder[0])
			s.chunkOrder = s.chunkOrder[1:]
		}
	}
	s.chunkCache[k] = plain
}

func (s *Store) chunkCacheDrop(hash string) {
	s.chunkMu.Lock()
	defer s.chunkMu.Unlock()
	if s.chunkCache == nil {
		return
	}
	kept := s.chunkOrder[:0]
	for _, k := range s.chunkOrder {
		if k.hash == hash {
			delete(s.chunkCache, k)
		} else {
			kept = append(kept, k)
		}
	}
	s.chunkOrder = kept
}

func (s *Store) Has(hash string) bool {
	_, err := os.Stat(s.pathFor(hash))
	return err == nil
}

func (s *Store) Remove(hash string) error {
	if hash == "" {
		return nil
	}
	s.chunkCacheDrop(hash)
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.pathFor(hash)
	var size int64
	if fi, err := os.Stat(path); err == nil {
		size = fi.Size()
	}
	err := os.Remove(path)
	if err == nil {
		s.bytes.Add(-size)
	}
	return err
}

func (s *Store) Size(hash string) (int64, error) {
	info, err := os.Stat(s.pathFor(hash))
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (s *Store) pathFor(hash string) string {
	if len(hash) < 4 {
		return filepath.Join(s.dir, hash)
	}
	return filepath.Join(s.dir, hash[:2], hash[2:])
}

func (s *Store) ListHashes() ([]string, error) {
	shards, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var hashes []string
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(s.dir, shard.Name()))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || fsutil.IsTempName(e.Name()) {
				continue
			}
			hashes = append(hashes, shard.Name()+e.Name())
		}
	}
	return hashes, nil
}

func (s *Store) GCTempFiles(minAge time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shards, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	cutoff := time.Now().Add(-minAge)
	removed := 0
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		shardDir := filepath.Join(s.dir, shard.Name())
		entries, err := os.ReadDir(shardDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !fsutil.IsTempName(e.Name()) {
				continue
			}
			info, ierr := e.Info()
			if ierr != nil || info.ModTime().After(cutoff) {
				continue
			}
			if os.Remove(filepath.Join(shardDir, e.Name())) == nil {
				removed++
			}
		}
	}
	return removed, nil
}

func (s *Store) CleanAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.RemoveAll(s.dir)
	s.bytes.Store(0)
	return err
}
