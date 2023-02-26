package types

import (
	"fmt"
"log"
	"golang.org/x/crypto/ssh"
)

type SignedCert struct {
	Cert []byte
}

func NewSignedCert(signingKey string, keyToSign string, signedKeyId string) (*SignedCert, error) {
	log.Println("made it in here too")
	return &SignedCert{
		Cert: []byte(fmt.Sprintf("key issued for %s", signedKeyId)),
	}, nil
}

func (s *SignedCert) Signer(signer ssh.Signer) (ssh.Signer, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey(s.Cert)
	if err != nil {
		return nil, err
	}

	return ssh.NewCertSigner(pk.(*ssh.Certificate), signer)
}
