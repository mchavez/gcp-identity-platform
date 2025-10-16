package model

type Token struct {
	Kind         string `json:"kind,omitempty"`
	LocalID      string `json:"localId,omitempty"`
	Email        string `json:"email,omitempty"`
	DisplayName  string `json:"displayName,omitempty"`
	IDToken      string `json:"idToken"`
	Registered   bool   `json:"registered,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresIn    string `json:"expiresIn,omitempty"`
	PublicKey    string `json:"publicKey,omitempty"`
}

type TokenPayload struct {
	Token             string `json:"token"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}
