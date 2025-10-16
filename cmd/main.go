package main

import (
	httpserver "gcp-identity-platform/internal/handler/httpserver"
	"log"

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()
	httpserver.RegisterRoutes(app)

	log.Println("Starting Fiber server on :8080...")
	if err := app.Listen(":8080"); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
