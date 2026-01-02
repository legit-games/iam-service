package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Client registration handler and swagger fragment

func (s *Server) HandleClientRegistrationRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return s.tokenError(w, errors.ErrInvalidRequest)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	dsn := strings.TrimSpace(os.Getenv("REG_DB_DSN"))
	if dsn == "" {
		w.WriteHeader(http.StatusNotImplemented)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "not_implemented",
			"error_description": "set REG_DB_DSN to enable PostgreSQL-backed client registration",
		})
	}

	var payload struct {
		Name                    string   `json:"name"`
		ClientSecret            string   `json:"client_secret"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "invalid JSON payload",
		})
	}
	clientID := models.LegitID()
	if strings.TrimSpace(payload.ClientSecret) == "" {
		payload.ClientSecret = genRandomHexText(32)
	}
	domain := ""
	if len(payload.RedirectURIs) > 0 {
		domain = payload.RedirectURIs[0]
	}
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_client_metadata",
			"error_description": "redirect_uris is required",
		})
	}
	// GORM connection
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("open db: %v", err),
		})
	}

	// Ensure 'name' column exists (Postgres) to avoid migration drift in tests/environments
	_ = db.WithContext(r.Context()).Exec(`ALTER TABLE IF EXISTS oauth2_clients ADD COLUMN IF NOT EXISTS name TEXT`).Error

	// Insert client without user_id column to match schema
	if err := db.WithContext(r.Context()).Exec(`INSERT INTO oauth2_clients (id, secret, domain, name, created_at) VALUES ($1, $2, $3, $4, NOW())`, clientID, payload.ClientSecret, domain, payload.Name).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("insert client: %v", err),
		})
	}

	resp := map[string]interface{}{
		"client_id":                  clientID,
		"client_secret":              payload.ClientSecret,
		"redirect_uris":              payload.RedirectURIs,
		"client_name":                payload.Name,
		"token_endpoint_auth_method": payload.TokenEndpointAuthMethod,
		"client_id_issued_at":        time.Now().Unix(),
	}
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(resp)
}

// genRandomHexText generates a hex string of n bytes length.
func genRandomHexText(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) swaggerRegisterPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "RFC 7591 Dynamic Client Registration",
			"description": "Registers a new OAuth2 client. Generates client_id as hyphenless UUID mapped from Snowflake.",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"client_secret":              map[string]interface{}{"type": "string"},
								"redirect_uris":              map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string", "format": "uri"}},
								"name":                       map[string]interface{}{"type": "string"},
								"token_endpoint_auth_method": map[string]interface{}{"type": "string"},
							},
							"required": []string{"redirect_uris"},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"201": map[string]interface{}{
					"description": "Client registered",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"client_id":                  map[string]interface{}{"type": "string", "description": "Hyphenless UUID string"},
									"client_secret":              map[string]interface{}{"type": "string"},
									"redirect_uris":              map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string", "format": "uri"}},
									"client_name":                map[string]interface{}{"type": "string"},
									"token_endpoint_auth_method": map[string]interface{}{"type": "string"},
									"client_id_issued_at":        map[string]interface{}{"type": "integer", "format": "int64"},
								},
							},
						},
					},
				},
				"501": map[string]interface{}{"description": "Not Implemented (REG_DB_DSN not set)"},
			},
		},
	}
}

// HandleClientRegistrationGin registers a new OAuth2 client via Gin.
func (s *Server) HandleClientRegistrationGin(c *gin.Context) {
	dsn := strings.TrimSpace(os.Getenv("REG_DB_DSN"))
	if dsn == "" {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "set REG_DB_DSN to enable PostgreSQL-backed client registration"})
		return
	}
	var payload struct {
		Name                    string   `json:"name"`
		ClientSecret            string   `json:"client_secret"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid JSON payload"})
		return
	}
	clientID := models.LegitID()
	if strings.TrimSpace(payload.ClientSecret) == "" {
		payload.ClientSecret = genRandomHexText(32)
	}
	domain := ""
	if len(payload.RedirectURIs) > 0 {
		domain = payload.RedirectURIs[0]
	}
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata", "error_description": "redirect_uris is required"})
		return
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("open db: %v", err)})
		return
	}
	_ = db.WithContext(c.Request.Context()).Exec(`ALTER TABLE IF EXISTS oauth2_clients ADD COLUMN IF NOT EXISTS name TEXT`).Error
	if err := db.WithContext(c.Request.Context()).Exec(`INSERT INTO oauth2_clients (id, secret, domain, name, created_at) VALUES ($1, $2, $3, $4, NOW())`, clientID, payload.ClientSecret, domain, payload.Name).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("insert client: %v", err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"client_id":                  clientID,
		"client_secret":              payload.ClientSecret,
		"redirect_uris":              payload.RedirectURIs,
		"client_name":                payload.Name,
		"token_endpoint_auth_method": payload.TokenEndpointAuthMethod,
		"client_id_issued_at":        time.Now().Unix(),
	})
}
