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

	"github.com/adrg/xdg"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
)

const APP_NAME = "sfmcauth"

const SFMC_AUTH_ENDPOINT = "192.168.0.1"
const SFMC_AUTH_PORT = "22"
const SFMC_AUTH_USER = "stensonb"

var KEY_PATH = filepath.Join(xdg.DataHome, APP_NAME)
var KEY_PATH_PRIV = filepath.Join(KEY_PATH, "id_ed25519")
var KEY_PATH_PUB = filepath.Join(KEY_PATH, "id_ed25519.pub")

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
	err = os.Mkdir(filepath.Dir(KEY_PATH_PRIV), 0755)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(KEY_PATH_PRIV, privateKey, 0400)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(KEY_PATH_PUB, authorizedKey, 0444)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func main() {
	if _, err := os.Stat(KEY_PATH_PRIV); err == nil {
		log.Println("keys exist.  using existing keys.")
	} else {
		log.Println("keys missing.  generating keys now...")
		buildKeypair()
	}

	log.Printf("keys in '%s'\n", KEY_PATH)

	content, err := ioutil.ReadFile(KEY_PATH_PUB)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("public key: %s", string(content))

	ssh_client()
}

func ssh_client() error {
	//TODO read this from DNS maybe?
	//var hostKey ssh.PublicKey

	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	key, err := os.ReadFile(KEY_PATH_PRIV)
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

		client, err := ssh.Dial("tcp", endpoint, config)
		if err != nil {
			return err
		}
		defer client.Close()

		log.Printf("granting network access for %v\n", strings.Split(client.LocalAddr().String(), ":")[0])

		log.Println(client.Wait())
	}

	return nil
}
