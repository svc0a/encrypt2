package sha256

import "crypto/sha256"

type Service interface {
	Encode(string) string
	private()
}

func New() Service {
	return &impl{}
}

type impl struct{}

func (i impl) Encode(s string) string {
	hash := sha256.Sum256([]byte(s))
	return string(hash[:])
}

func (i impl) private() {
	return
}
