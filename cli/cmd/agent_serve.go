package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"pigcloud/internal/agent"
	"pigcloud/internal/crypto"

	"github.com/spf13/cobra"
)

var agentServeCmd = &cobra.Command{
	Use:    "__agent-serve",
	Hidden: true,
	Args:   cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		ttlSec, _ := cmd.Flags().GetInt("ttl")

		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read keys: %v\n", err)
			os.Exit(1)
		}
		var spawn agent.SpawnKeys
		if err := json.Unmarshal(raw, &spawn); err != nil {
			fmt.Fprintf(os.Stderr, "parse keys: %v\n", err)
			os.Exit(1)
		}

		pubBytes := crypto.DecodeHexKey(spawn.PubHex, crypto.X25519KeySize)
		privBytes := crypto.DecodeHexKey(spawn.PrivHex, crypto.X25519KeySize)
		kyberPubBytes := crypto.DecodeHexKey(spawn.KyberPubHex, crypto.KyberPublicKeySize)
		kyberSeedBytes := crypto.DecodeHexKey(spawn.KyberSeedHex, crypto.KyberSeedSize)
		nameBytes := crypto.DecodeHexKey(spawn.NameKeyHex, crypto.NameKeySize)
		if pubBytes == nil || privBytes == nil || kyberPubBytes == nil || kyberSeedBytes == nil || nameBytes == nil {
			os.Exit(1)
		}

		signPubEd := crypto.DecodeHexKey(spawn.SignPubEdHex, crypto.Ed25519PKSize)
		signPrivEd := crypto.DecodeHexKey(spawn.SignPrivEdHex, crypto.Ed25519SKSize)
		signPubMl := crypto.DecodeHexKey(spawn.SignPubMlHex, crypto.Mldsa44PKSize)
		signPrivMl := crypto.DecodeHexKey(spawn.SignPrivMlHex, crypto.Mldsa44SKSize)

		var keys agent.KeyMaterial
		copy(keys.PublicKey[:], pubBytes)
		copy(keys.PrivateKey[:], privBytes)
		keys.KyberPublicKey = kyberPubBytes
		keys.KyberSeed = kyberSeedBytes
		keys.NameKey = nameBytes
		keys.SigningPublicKeyEd25519 = signPubEd
		keys.SigningPrivateKeyEd25519 = signPrivEd
		keys.SigningPublicKeyMldsa = signPubMl
		keys.SigningPrivateKeyMldsa = signPrivMl

		for i := range raw {
			raw[i] = 0
		}

		ttl := time.Duration(ttlSec) * time.Second
		if ttl <= 0 {
			ttl = time.Hour
		}

		agent.Serve(&keys, ttl)
	},
}

func init() {
	agentServeCmd.Flags().Int("ttl", 3600, "")
	rootCmd.AddCommand(agentServeCmd)
}
