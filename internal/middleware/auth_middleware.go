package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gcp-identity-platform/internal/model"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const GooglePublicSigningKeysEndpoint = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"

// JSON Web Key Sets (JWKS) structure
type JWKS struct {
	Keys []model.JWK `json:"keys"`
}

type MapHeader map[string]interface{}

// Cached keys to avoid fetching JWKS on every request
var (
	cachedKeys  = make(map[string]*rsa.PublicKey)
	gKeys       = make(map[string]*model.JWK)
	lastFetched time.Time
)

// AuthMiddleware verifies a GCP Identity Platform ID token and attaches claims to `c.Locals("claims")`
func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		projectID := os.Getenv("GCP_PROJECT_ID")
		if projectID == "" {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "GCP_PROJECT_ID environment variable not set"})
		}

		authHeader := c.Get("Authorization")
		ApiGatewayToken := c.Get("X-Apigateway-Api-Userinfo")
		// If Google Cloud API Gateway is set, get the original Authorization header
		if ApiGatewayToken != "" {
			XForwardedAuthHeader := c.Get("X-Forwarded-Authorization")
			if XForwardedAuthHeader != "" {
				authHeader = XForwardedAuthHeader
			}
		}

		// Check if the Authorization header is present and has the correct format
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid Authorization header"})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		header, claims, gcpKey, pem, err := verifyIDToken(tokenString, projectID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}

		c.Locals("header", header)
		c.Locals("claims", claims)
		c.Locals("jwk", gcpKey)
		c.Locals("pem_format", pem)
		return c.Next()
	}
}

func getPemFormat(pubKey *rsa.PublicKey) (string, error) {
	return encodePublicKeyToPEM(pubKey)
}

func verifyIDToken(tokenString, projectID string) (map[string]interface{}, jwt.MapClaims, *model.JWK, string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, nil, "", fmt.Errorf("invalid token format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid header encoding: %v", err)
	}

	var header MapHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid header JSON: %v", err)
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return nil, nil, nil, "", fmt.Errorf("kid not found in token header")
	}

	pubKey, gcpKey, err := getGooglePublicSigningKey(kid)
	if err != nil {
		return nil, nil, nil, "", err
	}

	pemData, err := getPemFormat(pubKey)
	if err != nil {
		return nil, nil, nil, "", err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("token verification failed: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, nil, nil, "", fmt.Errorf("invalid token claims")
	}

	if claims["aud"] != projectID {
		return nil, nil, nil, "", fmt.Errorf("invalid audience: %v", claims["aud"])
	}

	if claims["iss"] != fmt.Sprintf("https://securetoken.google.com/%s", projectID) {
		return nil, nil, nil, "", fmt.Errorf("invalid issuer: %v", claims["iss"])
	}

	return header, claims, gcpKey, pemData, nil
}

func encodePublicKeyToPEM(pubKey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	return strings.ReplaceAll(string(pemData), "\n", ""), nil
}

// getGooglePublicSigningKey fetches JWKS and caches it for 1 hour
func getGooglePublicSigningKey(kid string) (*rsa.PublicKey, *model.JWK, error) {
	if time.Since(lastFetched) > time.Hour {
		if err := refreshGooglePublicKeys(); err != nil {
			return nil, nil, err
		}
	}

	key, exists := cachedKeys[kid]
	if !exists {
		return nil, nil, fmt.Errorf("public key not found for kid: %s", kid)
	}

	return key, gKeys[kid], nil
}

// refreshGooglePublicKeys fetches Google’s public signing keys
func refreshGooglePublicKeys() error {
	resp, err := http.Get(GooglePublicSigningKeysEndpoint)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %v", err)
	}

	cachedKeys = make(map[string]*rsa.PublicKey)
	gKeys = make(map[string]*model.JWK)
	for _, key := range jwks.Keys {
		nb, _ := base64.RawURLEncoding.DecodeString(key.N)
		eb, _ := base64.RawURLEncoding.DecodeString(key.E)

		n := new(big.Int).SetBytes(nb)
		e := int(new(big.Int).SetBytes(eb).Uint64())
		cachedKeys[key.Kid] = &rsa.PublicKey{N: n, E: e}
		gKeys[key.Kid] = &key
	}

	lastFetched = time.Now()
	return nil
}

func GetPemFormatFromIDToken(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid header encoding: %v", err)
	}

	var header MapHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("invalid header JSON: %v", err)
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return "", fmt.Errorf("kid not found in token header")
	}

	pubKey, _, err := getGooglePublicSigningKey(kid)
	if err != nil {
		return "", err
	}

	pemData, err := getPemFormat(pubKey)
	if err != nil {
		return "", err
	}

	return pemData, nil
}
