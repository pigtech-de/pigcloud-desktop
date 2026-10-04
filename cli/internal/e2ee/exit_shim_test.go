package e2ee

import (
	"context"

	"pigcloud/internal/crypto"
)

func getKeyPair(exitFn func()) (*crypto.PublicKeySet, *crypto.PrivateKeySet) {
	pub, priv, err := GetKeyPair()
	if err != nil {
		exitFn()
		return nil, nil
	}
	return pub, priv
}

func getPublicKey(exitFn func()) *crypto.PublicKeySet {
	pub, err := GetPublicKey()
	if err != nil {
		exitFn()
		return nil
	}
	return pub
}

func getNameKey(exitFn func()) []byte {
	nameKey, err := GetNameKey()
	if err != nil {
		exitFn()
		return nil
	}
	return nameKey
}

func getSigningKeys(exitFn func()) (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	pub, priv, err := GetSigningKeys()
	if err != nil {
		exitFn()
		return nil, nil
	}
	return pub, priv
}

func addE2eeNameFields(options map[string]string, fileName, fullPath string, exitFn func()) {
	if err := AddE2eeNameFields(options, fileName, fullPath); err != nil {
		exitFn()
	}
}

func addE2eeNameFieldsForMkParents(options map[string]string, pathSegments []string, exitFn func()) {
	if err := AddE2eeNameFieldsForMkParents(options, pathSegments); err != nil {
		exitFn()
	}
}

func addPathTokens(options map[string]string, paths []string, exitFn func()) {
	if err := AddPathTokens(options, paths); err != nil {
		exitFn()
	}
}

func computePathTokenMaps(paths []string, exitFn func()) (string, string) {
	canonical, legacy, err := ComputePathTokenMaps(paths)
	if err != nil {
		exitFn()
		return "", ""
	}
	return canonical, legacy
}

func handleE2EEUpload(localPath string, exitFn func()) (encryptedPath, sealedKeyB64, encMetaB64, teeSealedKeyB64, plaintextHmacHex string) {
	artifacts, err := EncryptForUpload(context.Background(), localPath)
	if err != nil {
		exitFn()
		return "", "", "", "", ""
	}
	return artifacts.EncryptedPath, artifacts.SealedKeyB64, artifacts.EncMetaB64,
		artifacts.TeeSealedKeyB64, artifacts.PlaintextHmacHex
}

func signEncryptedFile(encryptedPath string, exitFn func()) (sigEdB64, sigMldsaB64, pkEdB64, pkMldsaB64 string) {
	sigs, err := SignEncryptedFile(encryptedPath)
	if err != nil {
		exitFn()
		return "", "", "", ""
	}
	return sigs.SignatureEd25519B64, sigs.SignatureMldsaB64,
		sigs.SigningPkEd25519B64, sigs.SigningPkMldsaB64
}
