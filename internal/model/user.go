package model

type User struct {
	Email             string `json:"email,omitempty"`
	Password          string `json:"password,omitempty"`
	ReturnSecureToken bool   `json:"returnSecureToken,omitempty"`
}
