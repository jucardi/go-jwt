package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"go.riotgames.com/ssp/go-jarvis/net/tokens/encoding"
)

type ecdsaSigner struct {
	alg       string
	hash      crypto.Hash
	keySize   int
	curveBits int
}

func (x *ecdsaSigner) Algorithm() string {
	return x.alg
}

func (x *ecdsaSigner) Sign(signingString string, privateKey interface{}) (string, error) {
	key, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().BitSize != x.curveBits {
		return "", errors.New("invalid key, expected *ecdsa.PrivateKey")
	}

	hasher := x.hash.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return r, s
	r, s, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	keyBytes := x.curveBits / 8
	if x.curveBits%8 > 0 {
		keyBytes += 1
	}

	// We serialize the outpus (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return encoding.EncodeSegment(out), nil
}

func (x *ecdsaSigner) Verify(signed, signature []byte, publicKey interface{}) error {
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok || len(signature) != 2*x.keySize {
		return errors.New("invalid key, expected *ecdsa.PublicKey")
	}

	hasher := x.hash.New()
	hasher.Write(signed)

	r := big.NewInt(0).SetBytes(signature[:x.keySize])
	s := big.NewInt(0).SetBytes(signature[x.keySize:])

	// Verify the signature
	if !ecdsa.Verify(key, hasher.Sum(nil), r, s) {
		return errors.New("token verification failed")
	}
	return nil
}
