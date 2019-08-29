package signing

type ISigner interface {
	Sign(signingString string, privateKey interface{}) (string, error)
	Verify(signed, signature []byte, publicKey interface{}) error
	Algorithm() string
}
