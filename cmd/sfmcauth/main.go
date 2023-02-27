package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/mikesmitty/edkey"
	"github.com/ravener/discord-oauth2"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/stensonb/sfmcauth/cmd/sfmcsigner/types"
)

const APP_NAME = "sfmcauth"

const SFMC_AUTH_SIGNER_URL = "http://localhost:8080/sign"
const SFMC_AUTH_ENDPOINT = "localhost" //"sf.siliconvortex.com"
const SFMC_AUTH_PORT = "22"
const SFMC_AUTH_USER = "sfmc_auth" //"sfmcauth"

var spin = spinner.New(spinner.CharSets[35], 100*time.Millisecond)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type KeyPair struct {
	PubKey  ssh.PublicKey
	privKey []byte
}

func (k *KeyPair) PublicKeyBytes() []byte {
	return ssh.MarshalAuthorizedKey(k.PubKey)
}

func (k *KeyPair) Signer() (ssh.Signer, error) {
	return ssh.ParsePrivateKey(k.privKey)
}

func NewKeyPair() (*KeyPair, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	// convert to ssh.PublicKey
	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	// convert to []byte
	privateKey := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey), // <- marshals ed25519 correctly
	})

	return &KeyPair{
		PubKey:  publicKey,
		privKey: privateKey,
	}, nil
}

type SignedCert struct {
	cert []byte
}

func (s *SignedCert) Signer(signer ssh.Signer) (ssh.Signer, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey(s.cert)
	if err != nil {
		return nil, err
	}

	return ssh.NewCertSigner(pk.(*ssh.Certificate), signer)
}

func GetSignedCert(k *KeyPair, oidc_code string) (*types.SignedCert, error) {
	csr, err := json.Marshal(types.CertSignRequest{
		OIDCCode:  oidc_code,
		PublicKey: string(k.PublicKeyBytes()),
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post("http://localhost:8080/sign", "application/json", bytes.NewReader(csr))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("call to get signed cert failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ans types.SignedCert

	err = json.Unmarshal(body, &ans)
	if err != nil {
		return nil, err
	}

	return &ans, nil
}

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != state {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("state does not match"))
		return
	}

	oidc_callback_code <- r.FormValue("code")

	w.Write([]byte("thanks.  you can close this window."))
}

var state = "somerandomstringhere"

var oidc_callback_code = make(chan string)

func main() {
	log.Printf("version %s, commit %s, built at %s", version, commit, date)

	k, err := NewKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	conf := &oauth2.Config{
		RedirectURL: "http://localhost:3000/auth/callback",
		ClientID:    "1066256314617053264",
		Scopes:      []string{discord.ScopeIdentify},
		Endpoint:    discord.Endpoint,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, conf.AuthCodeURL(state), http.StatusTemporaryRedirect)
	})

	http.HandleFunc("/auth/callback", HandleCallback)

	//TODO listen for a single connection, then shut it down
        //TODO extract listening port from conf
	go http.ListenAndServe(":3000", nil)

 	open.Run("http://localhost:3000")	

	oidc_code := <- oidc_callback_code

	signedCert, err := GetSignedCert(k, oidc_code)
	if err != nil {
		log.Fatal(err)
	}

	err = ssh_client(k, signedCert)
	if err != nil {
		log.Fatal(err)
	}
}

type SSHClient struct {
	KeyPair *KeyPair
}

func NewSSHClient(k *KeyPair) (*SSHClient, error) {
	return &SSHClient{
		KeyPair: k,
	}, nil
}

func ssh_client(k *KeyPair, signedCert *types.SignedCert) error {
	//TODO read this from DNS maybe?
	//var hostKey ssh.PublicKey

	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.

	signer, err := k.Signer()
	if err != nil {
		return err
	}

	certSigner, err := signedCert.Signer(signer)
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User: SFMC_AUTH_USER,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(certSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		//HostKeyCallback: ssh.FixedHostKey(hostKey),
	}

	// Connect to the remote server and perform the SSH handshake.
	endpoint := fmt.Sprintf("%s:%s", SFMC_AUTH_ENDPOINT, SFMC_AUTH_PORT)

	for {
		spin.Start()
		defer spin.Stop()
		var client *ssh.Client
		var err error

		firstPass := true
		for firstPass || err != nil {
			client, err = ssh.Dial("tcp", endpoint, config)
			if err != nil {
				// TODO exponential decay
				time.Sleep(10 * time.Second)
			}
			firstPass = false
		}

		spin.Stop()

		ip_addr := strings.Split(client.LocalAddr().String(), ":")
		log.Printf("minecraft server at '%s' should now be accessible from your ip ('%s').  keep this window open/running until you're done.", SFMC_AUTH_ENDPOINT, strings.Join(ip_addr[:len(ip_addr)-1], ":"))

		// Create a session
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()

		// Set up terminal modes
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}

		// Request pseudo terminal
		if err := session.RequestPty("xterm", 40, 80, modes); err != nil {
			return err
		}

		// Start remote shell to actually trigger /usr/sbin/authpf
		if err := session.Shell(); err != nil {
			return err
		}
		log.Println(client.Wait())
	}

	return nil
}
