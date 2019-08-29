package signing

import (
	"crypto"
	"crypto/hmac"
	"errors"

	"go.riotgames.com/ssp/go-jarvis/net/tokens/encoding"
)

type hmacSigner struct {
	alg  string
	hash crypto.Hash
}

func (r *hmacSigner) Algorithm() string {
	return r.alg
}

func (r *hmacSigner) Sign(signingString string, privateKey interface{}) (string, error) {
	key, ok := privateKey.([]byte)
	if !ok {
		return "", errors.New("invalid key, expected []byte")
	}

	hasher := hmac.New(r.hash.New, key)
	hasher.Write([]byte(signingString))

	return encoding.EncodeSegment(hasher.Sum(nil)), nil
}

func (r *hmacSigner) Verify(signed, signature []byte, publicKey interface{}) error {
	key, ok := publicKey.([]byte)
	if !ok {
		return errors.New("invalid key, expected []byte")
	}

	hasher := hmac.New(r.hash.New, key)
	hasher.Write(signed)

	if !hmac.Equal(signature, hasher.Sum(nil)) {
		return errors.New("invalid signature")
	}
	return nil
}
