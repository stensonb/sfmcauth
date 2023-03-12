package main

import (
	"context"
	"fmt"
	"io/ioutil"

	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"github.com/ravener/discord-oauth2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/stensonb/sfmcauth/api/types"
)

const OIDC_REDIRECT_URL = "http://localhost:3000/auth/callback"

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// TODO limit size of post
func signRequestHandler(c *gin.Context) {
	var csr types.CertSignRequest

	if err := c.ShouldBind(&csr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if signed, err := signCsr(csr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	} else {
		c.JSON(http.StatusOK, gin.H{"cert": signed})
	}
}

func signCsr(csr types.CertSignRequest) ([]byte, error) {
	discordIdentity, err := getIdentityFromCode(csr.OIDCCode)
	if err != nil {
		return nil, err
	}

	if !allowedAccess(discordIdentity) {
		return nil, fmt.Errorf("valid discord user prohibited from access: %v", discordIdentity)
	}

	log.Println(string(csr.PublicKey))

	signed, err := GetSignedCert(csr.PublicKey, discordIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to sign key: %w", err)
	}

	return json.Marshal(signed)
}

func allowedAccess(id *OIDCScope) bool {
	// TODO validate username against allowlist
	return true
}

func getIdentityFromCode(code string) (*OIDCScope, error) {
	client, err := NewOIDCClientWithCode(code)
	if err != nil {
		return nil, fmt.Errorf("error on getting OIDC client: %w", err)
	}

	res, err := client.Get("https://discord.com/api/users/@me")
	if err != nil || res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error calling GET on getting client: %w", err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to get response from discord endpoint: %w", err)
	}

	var discordIdentity OIDCScope

	err = json.Unmarshal(body, &discordIdentity)
	if err != nil {
		return nil, fmt.Errorf("unexpected response from discord: %w", err)
	}

	return &discordIdentity, nil
}

//	log.Printf("unmarshalled discord identity: %v", discordIdentity)

func GetSignedCert(keyToSign string, data *OIDCScope) (*types.SignedCert, error) {
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

	return types.NewSignedCert(signer, pubKey, signedKeyId)
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	gin.DisableConsoleColor()
	r := gin.Default()

	r.POST("/sign", signRequestHandler)

	log.Println("listening on :8080")
	r.Run(":8080")
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
