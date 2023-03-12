package types

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

type SignedCert struct {
	Cert []byte `json:"cert"`
}

func NewSignedCert(caKeySigner ssh.Signer, keyToSign ssh.PublicKey, signedKeyId string) (*SignedCert, error) {
	log.Printf("signing key for %s", signedKeyId)

	//principals := []string{"sfmcauth"}
	principals := []string{"sfmc_auth"}

	serial := uint64(time.Now().UnixNano())

	ttl := 24 * 60 * 60 // 1 day

	extensions := map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}

	certificate := ssh.Certificate{
		Serial:          serial,
		Key:             keyToSign,
		KeyId:           signedKeyId,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Unix() - 60),
		ValidBefore:     uint64(time.Now().Unix() + int64(ttl)),
		CertType:        ssh.UserCert,
		Permissions: ssh.Permissions{
			//			CriticalOptions: s.CriticalOptions,
			Extensions: extensions,
		},
	}

	err := certificate.SignCert(rand.Reader, caKeySigner)
	if err != nil {
		return nil, err
	}

	certBytes := ssh.MarshalAuthorizedKey(&certificate)
	if len(certBytes) == 0 {
		return nil, fmt.Errorf("failed to marshal signed certificate, empty result")
	}

	return &SignedCert{
		Cert: certBytes,
	}, nil
}

func (s *SignedCert) Signer(signer ssh.Signer) (ssh.Signer, error) {
	log.Println(string(s.Cert))
	pk, _, _, _, err := ssh.ParseAuthorizedKey(s.Cert)
	if err != nil {
		return nil, err
	}
	log.Println("made it here finally too?")

	return ssh.NewCertSigner(pk.(*ssh.Certificate), signer)
}
