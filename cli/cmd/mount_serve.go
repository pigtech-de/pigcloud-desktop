package cmd

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"pigcloud/internal/crypto"
	"pigcloud/internal/mount"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/daemon"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/spawn"

	"github.com/spf13/cobra"
)

var mountServeCmd = &cobra.Command{
	Use:    "__mount-serve",
	Hidden: true,
	Args:   cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		remotePath, _ := cmd.Flags().GetString("remote")
		mountPoint, _ := cmd.Flags().GetString("mountpoint")
		cacheSizeBytes, _ := cmd.Flags().GetInt64("cache-size")
		pollSec, _ := cmd.Flags().GetInt("poll")
		mode, _ := cmd.Flags().GetString("mode")
		readOnly, _ := cmd.Flags().GetBool("read-only")
		if lvl, ok := mlog.ParseLevel(cmd.Flags().Lookup("log-level").Value.String()); ok {
			mlog.SetLevel(lvl)
		}

		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read keys: %v\n", err)
			os.Exit(1)
		}
		var keys spawn.Keys
		if err := json.Unmarshal(raw, &keys); err != nil {
			fmt.Fprintf(os.Stderr, "parse keys: %v\n", err)
			os.Exit(1)
		}

		pubBytes := crypto.DecodeHexKey(keys.PubHex, crypto.X25519KeySize)
		privBytes := crypto.DecodeHexKey(keys.PrivHex, crypto.X25519KeySize)
		kyberPubBytes := crypto.DecodeHexKey(keys.KyberPubHex, crypto.KyberPublicKeySize)
		kyberSeedBytes := crypto.DecodeHexKey(keys.KyberSeedHex, crypto.KyberSeedSize)
		nameBytes := crypto.DecodeHexKey(keys.NameKeyHex, crypto.NameKeySize)
		if pubBytes == nil || privBytes == nil || kyberPubBytes == nil || kyberSeedBytes == nil || nameBytes == nil {
			os.Exit(1)
		}

		var x25519Pub, x25519Priv [32]byte
		copy(x25519Pub[:], pubBytes)
		copy(x25519Priv[:], privBytes)

		pub := &crypto.PublicKeySet{X25519: x25519Pub, Kyber: kyberPubBytes}
		priv := &crypto.PrivateKeySet{X25519: x25519Priv, Kyber: kyberSeedBytes}
		signPub, signPriv := decodeSigningKeys(keys)

		if cacheSizeBytes <= 0 {
			cacheSizeBytes = cache.DefaultMaxSize
		}
		if pollSec <= 0 {
			pollSec = 30
		}
		if mode == "" {
			mode = mount.ModeSync
		}

		cfg := &daemon.Config{
			MountPoint:        mountPoint,
			RemotePath:        remotePath,
			CacheSize:         cacheSizeBytes,
			PollInterval:      time.Duration(pollSec) * time.Second,
			PublicKey:         pub,
			PrivateKey:        priv,
			NameKey:           nameBytes,
			SigningPublicKey:  signPub,
			SigningPrivateKey: signPriv,
			Mode:              mode,
			ReadOnly:          readOnly,
		}

		var serveErr error
		if mode == mount.ModeVirtual {
			serveErr = daemon.ServeVirtual(cfg)
		} else {
			serveErr = daemon.ServeSync(cfg)
		}

		if serveErr != nil {
			fmt.Fprintf(os.Stderr, "mount daemon error: %v\n", serveErr)
			os.Exit(1)
		}
	},
}

func decodeSigningKeys(keys spawn.Keys) (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	pubEd := crypto.DecodeHexKey(keys.SignPubEdHex, crypto.Ed25519PKSize)
	privEd := crypto.DecodeHexKey(keys.SignPrivEdHex, crypto.Ed25519SKSize)
	pubMl := crypto.DecodeHexKey(keys.SignPubMlHex, crypto.Mldsa44PKSize)
	privMl := crypto.DecodeHexKey(keys.SignPrivMlHex, crypto.Mldsa44SKSize)
	if pubEd == nil || privEd == nil || pubMl == nil || privMl == nil {
		return nil, nil
	}
	var edPub [crypto.Ed25519PKSize]byte
	copy(edPub[:], pubEd)
	return &crypto.SigningPublicKeySet{Ed25519: edPub, Mldsa: pubMl},
		&crypto.SigningPrivateKeySet{Ed25519: ed25519.PrivateKey(privEd), Mldsa: privMl}
}

func init() {
	mountServeCmd.Flags().String("remote", "/", "")
	mountServeCmd.Flags().String("mountpoint", "", "")
	mountServeCmd.Flags().Int64("cache-size", cache.DefaultMaxSize, "")
	mountServeCmd.Flags().Int("poll", 30, "")
	mountServeCmd.Flags().String("mode", mount.ModeSync, "")
	mountServeCmd.Flags().Bool("read-only", false, "")
	mountServeCmd.Flags().String("log-level", "", "")
	rootCmd.AddCommand(mountServeCmd)
}
