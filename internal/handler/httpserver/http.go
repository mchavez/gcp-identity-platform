package httpserver

import (
	"gcp-identity-platform/internal/model"
	"gcp-identity-platform/internal/service"

	auth "gcp-identity-platform/internal/middleware" // Import the auth middleware

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// RegisterRoutes registers all Fiber routes for authentication
func RegisterRoutes(app *fiber.App) {
	// Define routes for user authentication
	app.Post("/login", handleLogin)
	app.Post("/validate-token", handleValidateToken)
	app.Post("/signup", handleSignUp)
	app.Post("/signup-anonymous", handleSignUpAnonymous)
	app.Post("/custom-token", handleSignInWithCustomToken)
	// Protect routes with GCP ID token authentication
	app.Use("/secure", auth.AuthMiddleware())
	// Secure decode token route
	app.Get("/secure/decode-token", handleDecodeToken)
	// Secure decode token route to get public key in PEM format
	app.Get("/secure/public-key", handlePemPublicKey)
}

// handleDecodeToken handles the decoding of the ID token
func handleDecodeToken(c *fiber.Ctx) error {
	claims := c.Locals("claims").(jwt.MapClaims)
	return c.JSON(fiber.Map{
		"message":               "User profile retrieved successfully",
		"claims":                claims,
		"header":                c.Locals("header"),
		"jwk":                   c.Locals("jwk"),
		"public_key_pem_format": c.Locals("pem_format"),
		"token":                 c.Get("Authorization"),
	})
}

// handlePemPublicKey handles the retrieval of the PEM format public key
func handlePemPublicKey(c *fiber.Ctx) error {
	jwk := c.Locals("jwk").(*model.JWK)
	return c.JSON(fiber.Map{
		"n":                     jwk.N, // In RS256, "n" represents the modulus of the RSA public key.
		"public_key_pem_format": c.Locals("pem_format"),
	})
}

// handleValidateToken validates an ID token using GCP identity-platform
func handleValidateToken(c *fiber.Ctx) error {
	var req model.Token
	if err := c.BodyParser(&req); err != nil {
		return respondWithError(c, fiber.StatusBadRequest, "Invalid request")
	}

	if req.IDToken == "" {
		return respondWithError(c, fiber.StatusBadRequest, "idToken is required")
	}

	claims, err := service.ValidateIDToken(req.IDToken)
	if err != nil {
		return respondWithError(c, fiber.StatusUnauthorized, err.Error())
	}

	return c.JSON(claims)
}

// handleLogin handles login requests using Fiber
func handleLogin(c *fiber.Ctx) error {
	var req model.User
	if err := c.BodyParser(&req); err != nil {
		return respondWithError(c, fiber.StatusBadRequest, "Invalid request")
	}

	resp, err := service.AuthenticateUser(req.Email, req.Password)
	if err != nil {
		return respondWithError(c, fiber.StatusUnauthorized, err.Error())
	}

	return c.JSON(resp)
}

// respondWithError is a utility function to send error responses
func respondWithError(c *fiber.Ctx, status int, message string) error {
	return c.Status(status).JSON(fiber.Map{"error": message})
}

// handleSignUp handles user registration using Fiber
func handleSignUp(c *fiber.Ctx) error {
	var req model.User
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	resp, err := service.SignUpUser(req.Email, req.Password)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

// handleSignUpAnonymous handles user registration using Fiber
func handleSignUpAnonymous(c *fiber.Ctx) error {
	var req model.User
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	resp, err := service.SignUpUser("", "")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

// handleSignInWithCustomToken authenticates a user using a custom token
func handleSignInWithCustomToken(c *fiber.Ctx) error {
	type reqBody struct {
		CustomToken string `json:"customToken"`
	}
	var req reqBody
	if err := c.BodyParser(&req); err != nil {
		return respondWithError(c, fiber.StatusBadRequest, "Invalid request")
	}

	if req.CustomToken == "" {
		return respondWithError(c, fiber.StatusBadRequest, "customToken is required")
	}

	resp, err := service.SignInWithCustomToken(req.CustomToken)
	if err != nil {
		return respondWithError(c, fiber.StatusUnauthorized, err.Error())
	}

	return c.JSON(resp)
}
