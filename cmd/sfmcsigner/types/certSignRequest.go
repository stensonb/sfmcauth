package types

type CertSignRequest struct {
	OIDCCode  string `json:"oidc_code"`
	PublicKey string `json:"key"`
}
