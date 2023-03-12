package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"github.com/mikesmitty/edkey"
	"github.com/ravener/discord-oauth2"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/stensonb/sfmcauth/api/types"
)

const APP_NAME = "sfmcauth"

const SFMC_AUTH_SIGNER_URL = "http://localhost:8080/sign"
const SFMC_AUTH_SUCCESSFUL_REDIRECT_URL = "https://sf.siliconvortex.com"
const SFMC_AUTH_ENDPOINT = "localhost" //"sf.siliconvortex.com"
const SFMC_AUTH_PORT = "22"
const SFMC_AUTH_USER = "sfmc_auth" //"sfmcauth"

const LOCAL_HTTP_SERVER = "localhost:3000"
const LOCAL_CALLBACK_PATH = "/auth/callback"

var spin = spinner.New(spinner.CharSets[35], 100*time.Millisecond)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

func GetSignedCert(k *KeyPair, oidc_code string) (*types.SignedCert, error) {
	csr, err := json.Marshal(types.CertSignRequest{
		OIDCCode:  oidc_code,
		PublicKey: string(k.PublicKeyBytes()),
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(SFMC_AUTH_SIGNER_URL, "application/json", bytes.NewReader(csr)) // from config?
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("call to get signed cert failed: %w", err)
	}
	defer resp.Body.Close()

	var ans types.SignedCert

	err = json.NewDecoder(resp.Body).Decode(&ans)
	if err != nil {
		return nil, err
	}

	return &ans, nil
}

type RespFromAuthProvider struct {
	Code  string `form:"code"`
	State string `form:"state"`
	//Error string `form:"error"`
}

func handleCallback(c *gin.Context) {
	resp := RespFromAuthProvider{}

	if c.ShouldBind(&resp) != nil {
		//log.Fatal("failed to decode authorization response from identity provider")
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("stuff"))
	} else if resp.Code == "" {
		//log.Fatal("failed to get authorization code from identity provider")
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("stuff2"))
	} else if resp.State != state {
		//log.Fatal("state does not match")
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("stuff3"))
	} else {
		oidc_callback_code <- resp.Code

		// TODO discord uses callback even on failure, but appends "error" query parameter
		// TODO handle this better
		c.Redirect(http.StatusTemporaryRedirect, SFMC_AUTH_SUCCESSFUL_REDIRECT_URL) // from config?
	}
}

var state string

var oidc_callback_code = make(chan string)

func main() {
	log.Printf("version %s, commit %s, built at %s", version, commit, date)

	k, err := NewKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	sha := sha256.New()
	sha.Write([]byte(string(uint64(time.Now().UnixNano()))))
	state = string(fmt.Sprintf("%x", sha.Sum(nil)))

	conf := &oauth2.Config{
		RedirectURL: fmt.Sprintf("http://%s%s", LOCAL_HTTP_SERVER, LOCAL_CALLBACK_PATH),
		ClientID:    "1066256314617053264", //delivered via config service?
		Scopes:      []string{discord.ScopeIdentify},
		Endpoint:    discord.Endpoint,
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, conf.AuthCodeURL(state))
	})

	router.GET(LOCAL_CALLBACK_PATH, handleCallback)

	srv := http.Server{
		Addr:    LOCAL_HTTP_SERVER,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen %s\n", err)
		}
	}()

	open.Run(fmt.Sprintf("http://%s", LOCAL_HTTP_SERVER))

	oidc_code := <-oidc_callback_code

	// got an oidc_code, shutdown http server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}

	signedCert, err := GetSignedCert(k, oidc_code)
	if err != nil {
		log.Fatal(err)
	}

	sshConfig, err := GetSshClientConfig(k, signedCert)
	if err != nil {
		log.Fatal(err)
	}

	err = ConnectSsh(sshConfig)
	if err != nil {
		log.Fatal(err)
	}
}

func GetSshClientConfig(k *KeyPair, signedCert *types.SignedCert) (*ssh.ClientConfig, error) {
	signer, err := k.Signer()
	if err != nil {
		return nil, err
	}

	log.Println("here")
	certSigner, err := signedCert.Signer(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer: %w", err)
	}
	log.Println("here too?")

	config := &ssh.ClientConfig{
		User: SFMC_AUTH_USER,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(certSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		//HostKeyCallback: ssh.FixedHostKey(hostKey),
	}

	return config, nil
}

func ConnectSsh(config *ssh.ClientConfig) error {
	//TODO read this from DNS maybe?
	//var hostKey ssh.PublicKey

	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.

	// Connect to the remote server and perform the SSH handshake.
	endpoint := fmt.Sprintf("%s:%s", SFMC_AUTH_ENDPOINT, SFMC_AUTH_PORT)
	log.Println("got here")
	for {
		spin.Start()
		defer spin.Stop()
		var client *ssh.Client
		var err error

		firstPass := true
		for firstPass || err != nil {
			client, err = ssh.Dial("tcp", endpoint, config)
			if err != nil {
				// TODO exponential delay
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
