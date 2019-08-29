package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
)

const (
	AlgorithmHS256 Algorithm = "HS256"
	AlgorithmHS384 Algorithm = "HS384"
	AlgorithmHS512 Algorithm = "HS512"
	AlgorithmRS256 Algorithm = "RS256"
	AlgorithmRS384 Algorithm = "RS384"
	AlgorithmRS512 Algorithm = "RS512"
	AlgorithmES256 Algorithm = "ES256"
	AlgorithmES384 Algorithm = "ES384"
	AlgorithmES512 Algorithm = "ES512"
)

// Algorithm indicates the signing algorithm to be used
type Algorithm string

// Signer returns the proper signer tied to the algorithm. If not found, returns nil
func (a Algorithm) Signer() ISigner {
	if ret, ok := signers[a]; ok {
		return ret
	}
	return nil
}

// String returns the string value of this instance
func (a Algorithm) String() string {
	return string(a)
}

var signers = map[Algorithm]ISigner{
	AlgorithmHS256: &hmacSigner{alg: "HS256", hash: crypto.SHA256},
	AlgorithmHS384: &hmacSigner{alg: "HS384", hash: crypto.SHA384},
	AlgorithmHS512: &hmacSigner{alg: "HS512", hash: crypto.SHA512},

	AlgorithmRS256: &rsaSigner{alg: "RS256", hash: crypto.SHA256},
	AlgorithmRS384: &rsaSigner{alg: "RS384", hash: crypto.SHA384},
	AlgorithmRS512: &rsaSigner{alg: "RS512", hash: crypto.SHA512},

	AlgorithmES256: &ecdsaSigner{alg: "ES256", hash: crypto.SHA256},
	AlgorithmES384: &ecdsaSigner{alg: "ES384", hash: crypto.SHA384},
	AlgorithmES512: &ecdsaSigner{alg: "ES512", hash: crypto.SHA512},
}

func DefaultFromKey(key interface{}) Algorithm {
	switch key.(type) {
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return AlgorithmES256
	case *rsa.PublicKey, *rsa.PrivateKey:
		return AlgorithmRS256
	case []byte:
		return AlgorithmHS256
	}
	return ""
}
