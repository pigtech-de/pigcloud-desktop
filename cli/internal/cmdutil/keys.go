package cmdutil

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/term"

	"pigcloud/internal/agent"
	"pigcloud/internal/agentkeys"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
)

type TerminalPrompter struct{}

func (TerminalPrompter) Password() ([]byte, error) {
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Print("Password: ")
		pwBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		return pwBytes, err
	}
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return []byte(scanner.Text()), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func InstallKeySeam() {
	e2ee.SetDefaultKeyAgent(agentkeys.New())
	e2ee.SetDefaultPasswordPrompter(TerminalPrompter{})
}

func fail(err error, exitFn func()) {
	output.PrintError(err.Error())
	exitFn()
}

func GetKeyPair(exitFn func()) (*crypto.PublicKeySet, *crypto.PrivateKeySet) {
	pub, priv, err := e2ee.GetKeyPair()
	if err != nil {
		fail(err, exitFn)
		return nil, nil
	}
	return pub, priv
}

func GetPublicKey(exitFn func()) *crypto.PublicKeySet {
	pub, err := e2ee.GetPublicKey()
	if err != nil {
		fail(err, exitFn)
		return nil
	}
	return pub
}

func GetSigningKeys(exitFn func()) (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	pub, priv, err := e2ee.GetSigningKeys()
	if err != nil {
		fail(err, exitFn)
		return nil, nil
	}
	return pub, priv
}

func GetNameKey(exitFn func()) []byte {
	nameKey, err := e2ee.GetNameKey()
	if err != nil {
		fail(err, exitFn)
		return nil
	}
	return nameKey
}

func GetParentKey(exitFn func()) []byte {
	parentKey, err := e2ee.GetParentKey()
	if err != nil {
		fail(err, exitFn)
		return nil
	}
	return parentKey
}

func AddE2eeNameFields(options map[string]string, fileName, fullPath string, exitFn func()) {
	if err := e2ee.AddE2eeNameFields(options, fileName, fullPath); err != nil {
		fail(err, exitFn)
	}
}

func AddE2eeNameFieldsForMkParents(options map[string]string, pathSegments []string, exitFn func()) {
	if err := e2ee.AddE2eeNameFieldsForMkParents(options, pathSegments); err != nil {
		fail(err, exitFn)
	}
}

func AddPathTokens(options map[string]string, paths []string, exitFn func()) {
	if err := e2ee.AddPathTokens(options, paths); err != nil {
		fail(err, exitFn)
	}
}

func AddPathTokensFor(options map[string]string, remotePath string, depth e2ee.Depth, exitFn func()) {
	if err := e2ee.AddPathTokensFor(options, remotePath, depth); err != nil {
		fail(err, exitFn)
	}
}

func AddPathTokensForAll(options map[string]string, remotePaths []string, depth e2ee.Depth, exitFn func()) {
	if err := e2ee.AddPathTokensForAll(options, remotePaths, depth); err != nil {
		fail(err, exitFn)
	}
}

func HandleE2EEUpload(ctx context.Context, localPath string, exitFn func()) *e2ee.UploadArtifacts {
	artifacts, err := e2ee.EncryptForUpload(ctx, localPath)
	if err != nil {
		fail(err, exitFn)
		return nil
	}
	return artifacts
}

func SignEncryptedFile(encryptedPath string, exitFn func()) (sigEdB64, sigMldsaB64, pkEdB64, pkMldsaB64 string) {
	sigs, err := e2ee.SignEncryptedFile(encryptedPath)
	if err != nil {
		fail(err, exitFn)
		return "", "", "", ""
	}
	return sigs.SignatureEd25519B64, sigs.SignatureMldsaB64,
		sigs.SigningPkEd25519B64, sigs.SigningPkMldsaB64
}

func PropagateSubtreeNamesAtPath(ctx context.Context, path string, exitFn func()) {
	if err := e2ee.PropagateSubtreeNamesAtPath(ctx, path); err != nil {
		fail(err, exitFn)
	}
}

func StartAgentForKeys(pub *crypto.PublicKeySet, priv *crypto.PrivateKeySet, nameKey []byte, signPub *crypto.SigningPublicKeySet, signPriv *crypto.SigningPrivateKeySet, ttl time.Duration) error {
	agent.Shutdown()

	var signPubEdHex, signPrivEdHex, signPubMlHex, signPrivMlHex string
	if signPub != nil && signPriv != nil {
		signPubEdHex = hex.EncodeToString(signPub.Ed25519[:])
		signPrivEdHex = hex.EncodeToString(signPriv.Ed25519)
		signPubMlHex = hex.EncodeToString(signPub.Mldsa)
		signPrivMlHex = hex.EncodeToString(signPriv.Mldsa)
	}

	if err := agent.SpawnBackground(agent.SpawnKeys{
		PubHex:        hex.EncodeToString(pub.X25519[:]),
		PrivHex:       hex.EncodeToString(priv.X25519[:]),
		KyberPubHex:   hex.EncodeToString(pub.Kyber),
		KyberSeedHex:  hex.EncodeToString(priv.Kyber),
		NameKeyHex:    hex.EncodeToString(nameKey),
		SignPubEdHex:  signPubEdHex,
		SignPrivEdHex: signPrivEdHex,
		SignPubMlHex:  signPubMlHex,
		SignPrivMlHex: signPrivMlHex,
	}, int(ttl.Seconds())); err != nil {
		return err
	}
	for range 10 {
		time.Sleep(100 * time.Millisecond)
		if agent.IsRunning() {
			return nil
		}
	}
	return fmt.Errorf("agent did not start")
}

func EnsureNamesReadable() bool {
	if e2ee.EnsureKeysFromAgent() {
		return true
	}
	if !e2ee.HasE2EEKeys() {
		output.PrintWarning("Encryption isn't set up for this account. Finish setup in the web app.")
		return false
	}
	if !term.IsTerminal(int(syscall.Stdin)) {
		output.PrintWarning("Encryption is locked: file names are hidden. Run 'pc uk' to unlock.")
		return false
	}
	output.PrintInfo("Encryption is locked. Unlock to view file names.")
	pub, priv, err := e2ee.GetKeyPair()
	if err != nil {
		output.PrintError(err.Error())
		return false
	}
	nameKey, err := e2ee.GetNameKey()
	if err != nil {
		output.PrintError(err.Error())
		return false
	}
	signPub, signPriv := e2ee.GetSigningKeysIfAvailable()
	if err := StartAgentForKeys(pub, priv, nameKey, signPub, signPriv, time.Hour); err != nil {
		output.PrintWarning("Unlocked for this command (agent didn't start, run 'pc uk' to persist).")
	}
	return true
}
