package mobile

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

type Enrolment struct {
	mu         sync.Mutex
	ephPub     []byte
	ephPriv    *crypto.PrivateKeySet
	deviceCode string
	interval   int
	expiresIn  int
	cancel     context.CancelFunc
	closed     bool
}

type enrolmentConfig struct {
	Endpoint    string `json:"endpoint"`
	ConfigDir   string `json:"config_dir"`
	Language    string `json:"language"`
	DeviceLabel string `json:"device_label"`
}

type enrolmentRequest struct {
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Commitment              string `json:"commitment"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type enrolmentResult struct {
	OK       bool   `json:"ok"`
	Message  string `json:"message"`
	APIKey   string `json:"api_key"`
	APIKeyID string `json:"api_key_id"`
	Material string `json:"material"`
	KeyEpoch int64  `json:"key_epoch"`
}

var (
	enrolMu   sync.Mutex
	enrolLive *Enrolment
)

func NewEnrolment(configJSON string) (e *Enrolment, err error) {
	defer recovered("NewEnrolment", &err)

	var cfg enrolmentConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("parse enrolment config: %w", err)
	}
	if cfg.ConfigDir == "" {
		return nil, errors.New("enrolment config needs a writable config_dir")
	}
	if err := os.MkdirAll(cfg.ConfigDir, 0700); err != nil {
		return nil, fmt.Errorf("create %s: %w", cfg.ConfigDir, err)
	}

	liveMu.Lock()
	sessionOpen := liveSession != nil
	liveMu.Unlock()
	if sessionOpen {
		return nil, errors.New("close the Session before enrolling this device")
	}

	enrolMu.Lock()
	defer enrolMu.Unlock()
	if enrolLive != nil {
		return nil, errors.New("an enrolment is already running in this process")
	}

	config.SetSecretStore(config.NewMemorySecretStore())
	config.SetConfigFile(filepath.Join(cfg.ConfigDir, "config.json"))
	config.Load()
	c := config.Get()
	if cfg.Endpoint != "" {
		c.Endpoint = cfg.Endpoint
	}
	if cfg.Language != "" {
		c.Language = cfg.Language
	}
	c.APIKey = ""

	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate the device key: %w", err)
	}
	ephPub := append(append([]byte{}, pub.X25519[:]...), pub.Kyber...)

	enrolLive = &Enrolment{ephPub: ephPub, ephPriv: priv}
	return enrolLive, nil
}

func (e *Enrolment) Request(deviceLabel string) (out string, err error) {
	defer recovered("Request", &err)

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return "", errors.New("this enrolment is closed")
	}
	if e.deviceCode != "" {
		e.mu.Unlock()
		return "", errors.New("this enrolment already has an open authorization")
	}
	ephPub := e.ephPub
	e.mu.Unlock()

	if deviceLabel == "" {
		deviceLabel = "PigCloud camera roll"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := api.NewClient().DeviceAuthorize(ctx, deviceLabel, base64.StdEncoding.EncodeToString(ephPub), true)
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return "", fmt.Errorf("device authorization refused: %s", resp.Error)
	}

	commitment := sha256.Sum256(ephPub)
	e.mu.Lock()
	e.deviceCode = resp.DeviceCode
	e.interval = resp.Interval
	e.expiresIn = resp.ExpiresIn
	e.mu.Unlock()

	return encodeJSON(enrolmentRequest{
		UserCode:                resp.UserCode,
		VerificationURI:         resp.VerificationURI,
		VerificationURIComplete: resp.VerificationURIComplete,
		Commitment:              base64.RawURLEncoding.EncodeToString(commitment[:]),
		Interval:                resp.Interval,
		ExpiresIn:               resp.ExpiresIn,
	})
}

func (e *Enrolment) Await(timeoutSeconds int) (out string, err error) {
	defer recovered("Await", &err)

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return "", errors.New("this enrolment is closed")
	}
	if e.deviceCode == "" {
		e.mu.Unlock()
		return "", errors.New("call Request before Await")
	}
	deviceCode, interval, expiresIn := e.deviceCode, e.interval, e.expiresIn
	if timeoutSeconds > 0 && timeoutSeconds < expiresIn {
		expiresIn = timeoutSeconds
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		e.cancel = nil
		e.mu.Unlock()
	}()

	claim, err := e.poll(ctx, deviceCode, interval, expiresIn)
	if err != nil {
		return encodeJSON(enrolmentResult{Message: err.Error()})
	}
	apiKey, sealedB64 := claim.APIKey, claim.SealedKey
	refuse := func(message string) (string, error) {
		releaseDeviceKey(apiKey, claim.KeyIdentifier)
		return encodeJSON(enrolmentResult{Message: message})
	}
	if sealedB64 == "" {
		return refuse("the approval carried no key material; enrol from a browser that has the account unlocked")
	}

	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return refuse("the sealed key material is not base64")
	}
	e.mu.Lock()
	ephPriv := e.ephPriv
	e.mu.Unlock()
	if ephPriv == nil {
		return refuse("this enrolment no longer holds its device key")
	}
	payload, err := crypto.HybridUnseal(sealed, ephPriv)
	if err != nil {
		return refuse("could not unseal the key material")
	}
	defer func() {
		for i := range payload {
			payload[i] = 0
		}
	}()
	material, err := crypto.ParseBackgroundKeyTransfer(payload)
	if err != nil {
		return refuse(err.Error())
	}
	material.Zero()

	return encodeJSON(enrolmentResult{
		OK:       true,
		APIKey:   apiKey,
		APIKeyID: claim.KeyIdentifier,
		Material: base64.StdEncoding.EncodeToString(payload),
		KeyEpoch: claim.KeyEpoch,
	})
}

func (e *Enrolment) poll(ctx context.Context, deviceCode string, interval, expiresIn int) (*api.DeviceTokenResult, error) {
	if interval < 1 {
		interval = 5
	}
	if expiresIn < 1 {
		expiresIn = 900
	}
	wait := time.Duration(interval) * time.Second
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)
	client := api.NewClient()

	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("enrolment cancelled")
		case <-time.After(wait):
		}
		if time.Now().After(deadline) {
			return nil, errors.New("the enrolment expired before it was approved")
		}
		resp, err := client.DeviceToken(ctx, deviceCode)
		if err != nil {
			continue
		}
		if resp.Success {
			return resp, nil
		}
		switch resp.Error {
		case "authorization_pending":
		case "slow_down":
			wait += 5 * time.Second
		case "access_denied":
			return nil, errors.New("the enrolment was declined")
		case "expired_token":
			return nil, errors.New("the enrolment expired before it was approved")
		default:
			return nil, fmt.Errorf("enrolment failed: %s", resp.Error)
		}
	}
}

func (e *Enrolment) Release(apiKey, keyIdentifier string) {
	releaseDeviceKey(apiKey, keyIdentifier)
}

func releaseDeviceKey(apiKey, keyIdentifier string) {
	if apiKey == "" || keyIdentifier == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = api.NewClientWithKey(apiKey).RevokeDeviceKey(ctx, keyIdentifier)
}

func (e *Enrolment) Cancel() {
	e.mu.Lock()
	cancel := e.cancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (e *Enrolment) Close() {
	e.Cancel()
	e.mu.Lock()
	if e.ephPriv != nil {
		e.ephPriv.Zero()
		e.ephPriv = nil
	}
	e.closed = true
	e.mu.Unlock()

	enrolMu.Lock()
	defer enrolMu.Unlock()
	if enrolLive == e {
		enrolLive = nil
	}
}

func (s *Session) UnlockBackground(materialB64 string) (err error) {
	defer recovered("UnlockBackground", &err)

	payload, err := base64.StdEncoding.DecodeString(materialB64)
	if err != nil {
		return fmt.Errorf("background key material is not base64: %w", err)
	}
	defer func() {
		for i := range payload {
			payload[i] = 0
		}
	}()
	material, err := crypto.ParseBackgroundKeyTransfer(payload)
	if err != nil {
		return err
	}
	defer material.Zero()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys.ClearCachedKey()
	return s.keys.UnlockBackground(material)
}

func (s *Session) BackgroundOnly() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys.IsBackground()
}
