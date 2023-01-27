package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/briandowns/spinner"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"

	qrcode "github.com/skip2/go-qrcode"
)

const APP_NAME = "sfmcauth"

const SFMC_AUTH_ENDPOINT = "sf.siliconvortex.com"
const SFMC_AUTH_PORT = "22"
const SFMC_AUTH_USER = "sfmcauth"
const SSH_KEY = "id_ed25519"
const SSH_KEY_PUBLIC = "id_ed25519.pub"

var PrivateKeyPath string
var PublicKeyPath string

var spin = spinner.New(spinner.CharSets[35], 100*time.Millisecond)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	var err error
	PrivateKeyPath, err = xdg.DataFile(filepath.Join(APP_NAME, SSH_KEY))
	if err != nil {
		log.Fatal(err)
	}

	PublicKeyPath, err = xdg.DataFile(filepath.Join(APP_NAME, SSH_KEY_PUBLIC))
	if err != nil {
		log.Fatal(err)
	}
}

func buildKeypair() error {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		log.Fatal(err)
	}

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey), // <- marshals ed25519 correctly
	}

	privateKey := pem.EncodeToMemory(pemKey)
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)

	// make dir if necessary
	err = os.Mkdir(filepath.Dir(PrivateKeyPath), 0755)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(PrivateKeyPath, privateKey, 0400)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(PublicKeyPath, authorizedKey, 0444)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func main() {
	log.Printf("version %s, commit %s, built at %s", version, commit, date)
	if _, err := os.Stat(PrivateKeyPath); err == nil {
		log.Println("keys exist.  using existing keys.")
	} else {
		log.Println("keys missing.  generating keys now...")
		buildKeypair()
	}

	log.Printf("public key in '%s'\n", PublicKeyPath)

	content, err := ioutil.ReadFile(PublicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	q, err := qrcode.New(string(content), qrcode.Low)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("\n%s\n", q.ToString(false))

	log.Print("share this public key with us on our Discord server to request access: ", string(content))

	err = ssh_client()
	if err != nil {
		log.Fatal(err)
	}

}

func ssh_client() error {
	//TODO read this from DNS maybe?
	//var hostKey ssh.PublicKey

	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	key, err := os.ReadFile(PrivateKeyPath)
	if err != nil {
		return err
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User: SFMC_AUTH_USER,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
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
