package agent

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/fsutil"
	"pigcloud/internal/netutil"
)

type AgentInfo struct {
	Port    int       `json:"port"`
	Token   string    `json:"token"`
	PID     int       `json:"pid"`
	Expires time.Time `json:"expires"`
}

type KeyMaterial struct {
	PublicKey      [32]byte
	PrivateKey     [32]byte
	KyberPublicKey []byte
	KyberSeed      []byte
	NameKey        []byte

	SigningPublicKeyEd25519  []byte
	SigningPrivateKeyEd25519 []byte
	SigningPublicKeyMldsa    []byte
	SigningPrivateKeyMldsa   []byte
}

type Request struct {
	Token  string `json:"token"`
	Action string `json:"action"`
}

type Response struct {
	OK             bool   `json:"ok"`
	Error          string `json:"error,omitempty"`
	PublicKey      string `json:"public_key,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	KyberPublicKey string `json:"kyber_public_key,omitempty"`
	KyberSeed      string `json:"kyber_seed,omitempty"`
	NameKey        string `json:"name_key,omitempty"`

	SigningPublicKeyEd25519  string `json:"signing_public_key_ed25519,omitempty"`
	SigningPrivateKeyEd25519 string `json:"signing_private_key_ed25519,omitempty"`
	SigningPublicKeyMldsa    string `json:"signing_public_key_mldsa,omitempty"`
	SigningPrivateKeyMldsa   string `json:"signing_private_key_mldsa,omitempty"`
}

func agentFilePath() string {
	return config.PathFor("agent.json")
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeAgentFile(info *AgentInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	path := agentFilePath()
	os.MkdirAll(filepath.Dir(path), 0700)
	return fsutil.WriteFileAtomic(path, data, 0600)
}

func ReadAgentFile() *AgentInfo {
	data, err := os.ReadFile(agentFilePath())
	if err != nil {
		return nil
	}
	var info AgentInfo
	if json.Unmarshal(data, &info) != nil {
		return nil
	}
	if info.Port == 0 || info.Token == "" {
		return nil
	}
	if !info.Expires.IsZero() && time.Now().After(info.Expires) {
		RemoveAgentFile()
		return nil
	}
	return &info
}

func RemoveAgentFile() {
	os.Remove(agentFilePath())
}

func Serve(keys *KeyMaterial, ttl time.Duration) (port int, token string, err error) {
	defer startLogging()()

	listener, err := net.Listen("tcp", netutil.LoopbackAny)
	if err != nil {
		return 0, "", fmt.Errorf("listen: %w", err)
	}
	return serveListener(listener, keys, ttl)
}

func serveListener(listener net.Listener, keys *KeyMaterial, ttl time.Duration) (port int, token string, err error) {
	token, err = generateToken()
	if err != nil {
		listener.Close()
		return 0, "", fmt.Errorf("generate token: %w", err)
	}
	port = listener.Addr().(*net.TCPAddr).Port

	expires := time.Now().Add(ttl)

	info := &AgentInfo{
		Port:    port,
		Token:   token,
		PID:     os.Getpid(),
		Expires: expires,
	}
	if err := writeAgentFile(info); err != nil {
		listener.Close()
		return 0, "", fmt.Errorf("write agent file: %w", err)
	}

	guard := newKeyGuard(keys)

	var shutdownOnce sync.Once
	shutdown := func(reason string) {
		shutdownOnce.Do(func() {
			log.Printf("%s: %s", wipeLogPrefix, reason)
			listener.Close()
			RemoveAgentFile()
			guard.wipe()
		})
	}

	timer := time.AfterFunc(ttl, func() {
		shutdown(fmt.Sprintf("ttl %s elapsed", ttl))
	})

	var backoff netutil.AcceptBackoff
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			d := backoff.Next()
			log.Printf("agent: accept failed, retrying in %v: %v", d, err)
			time.Sleep(d)
			continue
		}
		backoff.Reset()
		go handleConn(conn, guard, token, timer, shutdown)
	}

	shutdown("listener closed")
	return port, token, nil
}

const wipeLogPrefix = "agent: wiping keys and stopping"

type keyGuard struct {
	mu   sync.Mutex
	keys *KeyMaterial
}

func newKeyGuard(keys *KeyMaterial) *keyGuard {
	return &keyGuard{keys: keys}
}

func (g *keyGuard) response() (Response, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	k := g.keys
	if k == nil {
		return Response{}, false
	}
	return Response{
		OK:                       true,
		PublicKey:                hex.EncodeToString(k.PublicKey[:]),
		PrivateKey:               hex.EncodeToString(k.PrivateKey[:]),
		KyberPublicKey:           hex.EncodeToString(k.KyberPublicKey),
		KyberSeed:                hex.EncodeToString(k.KyberSeed),
		NameKey:                  hex.EncodeToString(k.NameKey),
		SigningPublicKeyEd25519:  hex.EncodeToString(k.SigningPublicKeyEd25519),
		SigningPrivateKeyEd25519: hex.EncodeToString(k.SigningPrivateKeyEd25519),
		SigningPublicKeyMldsa:    hex.EncodeToString(k.SigningPublicKeyMldsa),
		SigningPrivateKeyMldsa:   hex.EncodeToString(k.SigningPrivateKeyMldsa),
	}, true
}

func (g *keyGuard) wipe() {
	g.mu.Lock()
	defer g.mu.Unlock()

	k := g.keys
	if k == nil {
		return
	}
	for i := range k.PrivateKey {
		k.PrivateKey[i] = 0
	}
	for i := range k.KyberSeed {
		k.KyberSeed[i] = 0
	}
	for i := range k.NameKey {
		k.NameKey[i] = 0
	}
	for i := range k.SigningPrivateKeyEd25519 {
		k.SigningPrivateKeyEd25519[i] = 0
	}
	for i := range k.SigningPrivateKeyMldsa {
		k.SigningPrivateKeyMldsa[i] = 0
	}
	g.keys = nil
}

func handleConn(conn net.Conn, guard *keyGuard, token string, timer *time.Timer, shutdown func(string)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var req Request
	if err := dec.Decode(&req); err != nil {
		enc.Encode(Response{Error: "invalid request"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(token)) != 1 {
		enc.Encode(Response{Error: "unauthorized"})
		return
	}

	switch req.Action {
	case "ping":
		enc.Encode(Response{OK: true})

	case "keys":
		resp, ok := guard.response()
		if !ok {
			enc.Encode(Response{Error: "agent expired"})
			return
		}
		enc.Encode(resp)

	case "shutdown":
		enc.Encode(Response{OK: true})
		timer.Stop()
		go func() {
			time.Sleep(100 * time.Millisecond)
			shutdown("shutdown requested")
		}()

	default:
		enc.Encode(Response{Error: "unknown action"})
	}
}

func RequestKeys() *KeyMaterial {
	info := ReadAgentFile()
	if info == nil {
		return nil
	}

	resp, err := sendRequest(info, "keys")
	if err != nil || !resp.OK {
		return nil
	}

	pubBytes := crypto.DecodeHexKey(resp.PublicKey, crypto.X25519KeySize)
	privBytes := crypto.DecodeHexKey(resp.PrivateKey, crypto.X25519KeySize)
	kyberPubBytes := crypto.DecodeHexKey(resp.KyberPublicKey, crypto.KyberPublicKeySize)
	kyberSeedBytes := crypto.DecodeHexKey(resp.KyberSeed, crypto.KyberSeedSize)
	nameBytes := crypto.DecodeHexKey(resp.NameKey, crypto.NameKeySize)
	if pubBytes == nil || privBytes == nil || kyberPubBytes == nil || kyberSeedBytes == nil || nameBytes == nil {
		return nil
	}

	signingPubEd := crypto.DecodeHexKey(resp.SigningPublicKeyEd25519, crypto.Ed25519PKSize)
	signingPrivEd := crypto.DecodeHexKey(resp.SigningPrivateKeyEd25519, crypto.Ed25519SKSize)
	signingPubMl := crypto.DecodeHexKey(resp.SigningPublicKeyMldsa, crypto.Mldsa44PKSize)
	signingPrivMl := crypto.DecodeHexKey(resp.SigningPrivateKeyMldsa, crypto.Mldsa44SKSize)

	var pub, priv [32]byte
	copy(pub[:], pubBytes)
	copy(priv[:], privBytes)
	return &KeyMaterial{
		PublicKey:                pub,
		PrivateKey:               priv,
		KyberPublicKey:           kyberPubBytes,
		KyberSeed:                kyberSeedBytes,
		NameKey:                  nameBytes,
		SigningPublicKeyEd25519:  signingPubEd,
		SigningPrivateKeyEd25519: signingPrivEd,
		SigningPublicKeyMldsa:    signingPubMl,
		SigningPrivateKeyMldsa:   signingPrivMl,
	}
}

func Ping() bool {
	info := ReadAgentFile()
	if info == nil {
		return false
	}
	resp, err := sendRequest(info, "ping")
	return err == nil && resp.OK
}

func Shutdown() error {
	info := ReadAgentFile()
	if info == nil {
		return nil
	}
	_, err := sendRequest(info, "shutdown")
	RemoveAgentFile()
	return err
}

func IsRunning() bool {
	return Ping()
}

func sendRequest(info *AgentInfo, action string) (*Response, error) {
	conn, err := net.DialTimeout("tcp", netutil.LoopbackHost+":"+strconv.Itoa(info.Port), netutil.LoopbackDialTimeout)
	if err != nil {
		RemoveAgentFile()
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(Request{Token: info.Token, Action: action}); err != nil {
		return nil, err
	}

	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
