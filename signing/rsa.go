package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/jucardi/go-jwt/encoding"
)

type rsaSigner struct {
	alg  string
	hash crypto.Hash
}

func (r *rsaSigner) Algorithm() string {
	return r.alg
}

func (r *rsaSigner) Sign(signingString string, privateKey interface{}) (string, error) {
	// Validate type of key
	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("invalid key, expected *rsa.PrivateKey")
	}

	hasher := r.hash.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, r.hash, hasher.Sum(nil)); err == nil {
		return encoding.EncodeSegment(sigBytes), nil
	} else {
		return "", err
	}
}

func (r *rsaSigner) Verify(signed, signature []byte, publicKey interface{}) error {
	key, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid key, expected *rsa.PublicKey")
	}

	hasher := r.hash.New()
	hasher.Write(signed)

	return rsa.VerifyPKCS1v15(key, r.hash, hasher.Sum(nil), signature)
}
