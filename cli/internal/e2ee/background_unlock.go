package e2ee

import (
	"bytes"

	"pigcloud/internal/crypto"
)

var ErrBackgroundKeysIncomplete = &Fault{Message: "Background key material is incomplete. Re-enrol this device from the web app."}

var ErrBackgroundUploadOnly = &Fault{Message: "This device holds upload-only keys. Decryption needs the account password."}

func (s *Session) UnlockBackground(material *crypto.BackgroundKeyMaterial) error {
	if material == nil || len(material.NameKey) != crypto.NameKeySize ||
		len(material.ParentKey) != crypto.NameKeySize ||
		material.Pub == nil || len(material.Pub.Kyber) != crypto.KyberPublicKeySize ||
		material.SigningPriv == nil || material.SigningPub == nil {
		return ErrBackgroundKeysIncomplete
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.priv != nil {
		s.priv.Zero()
		s.priv = nil
	}
	s.pub = clonePublicKeySet(material.Pub)
	s.nameKey = bytes.Clone(material.NameKey)
	s.parentKey = bytes.Clone(material.ParentKey)
	s.signingPriv = cloneSigningPrivateKeySet(material.SigningPriv)
	s.signingPub = cloneSigningPublicKeySet(material.SigningPub)
	s.background = true
	return nil
}

func (s *Session) IsBackground() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.background
}
