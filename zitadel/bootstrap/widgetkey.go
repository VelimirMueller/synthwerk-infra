package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
)

// EnsureWidgetKey writes a new ECDSA P-256 private key (PKCS #8 PEM) to path when
// no file is there: the key synthwerk-identity signs widget tokens with
// (SYNTHWERK_IDENTITY_WIDGET_SIGNING_KEY_FILE, synthwerk#30). An existing file is
// kept, so the key set stays the same across restarts. The file gets mode 0400
// and owner, like the other keys identity reads. It returns true when it made a key.
func EnsureWidgetKey(path string, owner int) (bool, error) {
	// Stat, not read: root without CAP_DAC_OVERRIDE cannot read the 0400 file of owner.
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return true, writeKey(path, string(block), owner)
}
