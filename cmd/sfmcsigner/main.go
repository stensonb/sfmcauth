package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ravener/discord-oauth2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/stensonb/sfmcauth/cmd/sfmcsigner/types"
)

const OIDC_REDIRECT_URL = "http://localhost:3000/auth/callback"

// TODO limit size of post
func signRequestHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "not post", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	/*
	   // TODO figure this out
	   	if http.DetectContentType(body) != "application/json" {
	   		log.Println(http.DetectContentType(body))
	   		http.Error(w, "invalid content-type", http.StatusUnsupportedMediaType)
	   		return
	   	}
	*/

	var csr types.CertSignRequest

	err = json.Unmarshal(body, &csr)
	if err != nil {
		log.Printf("failed to unmarshal: %s", string(body))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	log.Println(string(body))

	client, err := NewOIDCClientWithCode(csr.OIDCCode)
	if err != nil {
		log.Println("error on getting OIDC client")
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	// TODO some client call to get username
	res, err := client.Get("https://discord.com/api/users/@me")
	if err != nil || res.StatusCode != http.StatusOK {
		log.Println("error calling GET on getting client")
		http.Error(w, "discord endpoint failed", http.StatusInternalServerError)
		return

	}
	defer res.Body.Close()

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		http.Error(w, "failed to get response from discord endpoint", http.StatusInternalServerError)
		return
	}

	log.Printf("discord response %s", string(body))

	// TODO validate username against allowlist

	var discordIdentity OIDCScope

	err = json.Unmarshal(body, &discordIdentity)
	if err != nil {
		log.Printf("unexpected response from discord: %s", string(body))
		http.Error(w, "internal error", http.StatusInternalServerError)
	}

	log.Printf("%v", discordIdentity)

	signed, err := GetSignedCert(csr.PublicKey, discordIdentity)
	if err != nil {
		http.Error(w, "failed to sign key", http.StatusBadRequest)
	}

	//	log.Printf("%v", string(signed.Cert))

	signedBytes, err := json.Marshal(signed)
	if err != nil {
		http.Error(w, "failed to unmarshal key", http.StatusInternalServerError)
	}

	log.Println(string(signedBytes))
	fmt.Fprintf(w, string(signedBytes))
}

func GetSignedCert(keyToSign string, data OIDCScope) (*types.SignedCert, error) {
	signedKeyId := strings.Join([]string{data.Id, data.Username}, "-")

	key, err := os.ReadFile("test_fixtures/id_ed25519")
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	// convert keyToSign to ssh.PublicKey
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyToSign))
	if err != nil {
		return nil, err
	}

	log.Printf("%v", pubKey)

	return types.NewSignedCert(signer, pubKey, signedKeyId)
}

func validateOIDCCode(code string) error {
	log.Println("validating OIDC code")
	return nil
}

func main() {
	http.HandleFunc("/sign", signRequestHandler)

	// TODO handle shutdowns cleanly with timeout
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func NewOIDCClientWithCode(code string) (*http.Client, error) {
	ctx := context.Background()

	cfg := oauth2.Config{
		RedirectURL:  OIDC_REDIRECT_URL,
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		Scopes:       []string{discord.ScopeIdentify},
		Endpoint:     discord.Endpoint,
	}

	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("error exchanging token: %w", err)
	}

	return cfg.Client(ctx, tok), err
}

type OIDCScope struct {
	Id       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}
