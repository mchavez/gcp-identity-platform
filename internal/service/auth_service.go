package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"gcp-identity-platform/internal/middleware"
	"gcp-identity-platform/internal/model"
)

const (
	signUpURL       = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key="
	signInURL       = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="
	lookupURL       = "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key="
	signInCustomURL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key="
)

// getGCPKey retrieves the API key from environment variables.
func getGCPKey(name string) (string, error) {
	apiKey := os.Getenv(name)
	if apiKey == "" {
		return "", fmt.Errorf("%s API key not set in environment variables", name)
	}
	return apiKey, nil
}

// postRequest sends a POST request to the specified URL with the given payload.
func postRequest(url string, payload interface{}) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return http.Post(url, "application/json", bytes.NewBuffer(body))
}

// handleErrorResponse processes the error response from the HTTP request.
func handleErrorResponse(httpResp *http.Response) error {
	defer httpResp.Body.Close()
	var errResp map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&errResp); err != nil {
		return err
	}

	if errMsg, ok := errResp["error"].(map[string]interface{}); ok {
		if msg, ok := errMsg["message"].(string); ok {
			return fmt.Errorf("error: %s", msg)
		}
	}

	return errors.New("unknown error occurred")
}

// ValidateIDToken validates a Google ID token using the Identity Platform accounts:lookup endpoint.
// https://cloud.google.com/identity-platform/docs/use-rest-api#section-get-account-info
func ValidateIDToken(idToken string) (map[string]interface{}, error) {
	apiKey, err := getGCPKey("GCP_IDENTITY_API_KEY")
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s%s", lookupURL, apiKey)
	payload := model.Token{IDToken: idToken}
	httpResp, err := postRequest(url, payload)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(httpResp)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// AuthenticateUser authenticates a user with their email and password.
// https://cloud.google.com/identity-platform/docs/use-rest-api#section-sign-in-email-password
func AuthenticateUser(email, password string) (*model.Token, error) {
	apiKey, err := getGCPKey("GCP_IDENTITY_API_KEY")
	if err != nil {
		return nil, err
	}

	showPublicKey, err := getGCPKey("GCP_SHOW_PUBLIC_KEYS")
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s%s", signInURL, apiKey)
	payload := model.User{
		Email:             email,
		Password:          password,
		ReturnSecureToken: true,
	}
	httpResp, err := postRequest(url, payload)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(httpResp)
	}

	var token model.Token
	if err := json.NewDecoder(httpResp.Body).Decode(&token); err != nil {
		return nil, err
	}

	if showKey, err := strconv.ParseBool(showPublicKey); err == nil && showKey {
		token.PublicKey, err = middleware.GetPemFormatFromIDToken(token.IDToken)
		if err != nil {
			return nil, err
		}
	}

	return &token, nil
}

// SignUpUser registers a new user using Google Identity Platform.
// https://cloud.google.com/identity-platform/docs/use-rest-api#section-create-email-password
func SignUpUser(email, password string) (*model.Token, error) {
	payload := model.User{ReturnSecureToken: true}
	apiKey, err := getGCPKey("GCP_IDENTITY_API_KEY")
	if err != nil {
		return nil, err
	}

	showPublicKey, err := getGCPKey("GCP_SHOW_PUBLIC_KEYS")
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s%s", signUpURL, apiKey)
	if email != "" && password != "" {
		payload.Email = email
		payload.Password = password
	}

	httpResp, err := postRequest(url, payload)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(httpResp)
	}

	var token model.Token
	if err := json.NewDecoder(httpResp.Body).Decode(&token); err != nil {
		return nil, err
	}

	if showKey, err := strconv.ParseBool(showPublicKey); err == nil && showKey {
		token.PublicKey, err = middleware.GetPemFormatFromIDToken(token.IDToken)
		if err != nil {
			return nil, err
		}
	}

	return &token, nil
}

// SignInWithCustomToken authenticates a user using a custom token via Google Identity Platform.
// https://cloud.google.com/identity-platform/docs/use-rest-api#section-sign-in-custom-token
func SignInWithCustomToken(customToken string) (map[string]interface{}, error) {
	apiKey, err := getGCPKey("GCP_IDENTITY_API_KEY")
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s%s", signInCustomURL, apiKey)
	payload := model.TokenPayload{
		Token:             customToken,
		ReturnSecureToken: true,
	}
	httpResp, err := postRequest(url, payload)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, errors.New("signInWithCustomToken failed")
	}

	var respBody map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&respBody); err != nil {
		return nil, err
	}

	return respBody, nil
}
