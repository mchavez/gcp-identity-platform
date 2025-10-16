package model

// JSON Web Tokens (JWT)
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}
