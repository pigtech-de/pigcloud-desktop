package e2ee

import (
	"context"

	"pigcloud/internal/crypto"
)

func GetKeyPair() (*crypto.PublicKeySet, *crypto.PrivateKeySet, error) {
	return defaultSession.KeyPair()
}

func GetPublicKey() (*crypto.PublicKeySet, error) { return defaultSession.PublicKey() }

func GetSigningKeys() (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet, error) {
	return defaultSession.SigningKeys()
}

func GetSigningKeysIfAvailable() (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	return defaultSession.SigningKeysIfAvailable()
}

func GetNameKey() ([]byte, error) { return defaultSession.NameKey() }

func GetParentKey() ([]byte, error) { return defaultSession.ParentKey() }

func EnsureKeysFromAgent() bool { return defaultSession.EnsureKeysFromAgent() }

func ClearCachedKey() { defaultSession.ClearCachedKey() }

func SetSuppliedPassword(pw []byte) { defaultSession.SetSuppliedPassword(pw) }

func ImportDeviceTransferredKeys(sealedB64 string, ephPriv *crypto.PrivateKeySet) error {
	return defaultSession.ImportDeviceTransferredKeys(sealedB64, ephPriv)
}

func DecryptE2EEName(e2eeDisplayNameB64 string) string {
	return defaultSession.DecryptE2EEName(e2eeDisplayNameB64)
}

func TeeScannerDisabledByServer() bool { return defaultSession.TeeScannerDisabledByServer() }

func TeeEnclaveKeyRefusal() error { return defaultSession.TeeEnclaveKeyRefusal() }

func FetchTeeEnclaveKeySet(ctx context.Context) *crypto.PublicKeySet {
	return defaultSession.FetchTeeEnclaveKeySet(ctx)
}

func TeeSealWentStale(ctx context.Context, err error, sealedTo *crypto.PublicKeySet) (bool, error) {
	return defaultSession.TeeSealWentStale(ctx, err, sealedTo)
}

func AddE2eeNameFields(options map[string]string, fileName, fullPath string) error {
	return defaultSession.AddE2eeNameFields(options, fileName, fullPath)
}

func AddE2eeNameFieldsForMkParents(options map[string]string, pathSegments []string) error {
	return defaultSession.AddE2eeNameFieldsForMkParents(options, pathSegments)
}

func ComputePathTokenMaps(paths []string) (canonicalJSON, legacyJSON string, err error) {
	return defaultSession.ComputePathTokenMaps(paths)
}

func AddPathTokens(options map[string]string, paths []string) error {
	return defaultSession.AddPathTokens(options, paths)
}

func AddPathTokensFor(options map[string]string, remotePath string, depth Depth) error {
	return defaultSession.AddPathTokensFor(options, remotePath, depth)
}

func AddPathTokensForAll(options map[string]string, remotePaths []string, depth Depth) error {
	return defaultSession.AddPathTokensForAll(options, remotePaths, depth)
}

func EncryptForUpload(ctx context.Context, localPath string) (*UploadArtifacts, error) {
	return defaultSession.EncryptForUpload(ctx, localPath)
}

func SignEncryptedFile(encryptedPath string) (*UploadSignatures, error) {
	return defaultSession.SignEncryptedFile(encryptedPath)
}

func PropagateSubtreeNamesAtPath(ctx context.Context, path string) error {
	return defaultSession.PropagateSubtreeNamesAtPath(ctx, path)
}
