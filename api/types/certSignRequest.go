package types

type CertSignRequest struct {
	OIDCCode  string `json:"oidc_code" binding:"required"`
	PublicKey string `json:"key" binding:"required"`
}
