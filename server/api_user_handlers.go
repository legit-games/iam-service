package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/models"
	"golang.org/x/crypto/bcrypt"
)

// JSON API handlers and swagger fragments

// HandleAPIRegisterUser registers a new user.
func (s *Server) HandleAPIRegisterUser(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "invalid JSON payload",
		})
	}
	payload.Username = strings.TrimSpace(payload.Username)
	payload.Password = strings.TrimSpace(payload.Password)
	if payload.Username == "" || payload.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "username and password are required",
		})
	}

	dbRead, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]interface{}{"error": "not_implemented", "error_description": "set USER_DB_DSN (or MIGRATE_DSN) to enable user registration"})
		}
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{"error": "server_error", "error_description": fmt.Sprintf("open db: %v", err)})
	}
	var exists int
	res := dbRead.WithContext(r.Context()).Raw(`SELECT 1 FROM accounts WHERE username=$1 LIMIT 1`, payload.Username)
	// Scan into exists; if no rows, Scan returns ErrRecordNotFound in GORM v2 when using First
	if err := res.Row().Scan(&exists); err == nil {
		w.WriteHeader(http.StatusConflict)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "conflict",
			"error_description": "username already exists",
		})
	}
	userID := models.LegitID()
	hash, _ := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	dbWrite, err := s.GetIAMWriteDB()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("open db: %v", err),
		})
	}
	// insert via raw SQL
	if err := dbWrite.WithContext(r.Context()).Exec(`INSERT INTO accounts (id, username, password_hash) VALUES ($1, $2, $3)`, userID, payload.Username, string(hash)).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("insert user: %v", err),
		})
	}

	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(map[string]interface{}{"user_id": userID})
}

// HandleAPIRegisterUserGin registers a new user via Gin.
func (s *Server) HandleAPIRegisterUserGin(c *gin.Context) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid JSON payload"})
		return
	}
	payload.Username = strings.TrimSpace(payload.Username)
	payload.Password = strings.TrimSpace(payload.Password)
	if payload.Username == "" || payload.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "username and password are required"})
		return
	}
	dbRead, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			NotImplementedGin(c, "set USER_DB_DSN or MIGRATE_DSN to enable user registration")
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("open db: %v", err)})
		return
	}
	var exists int
	if err := dbRead.WithContext(c.Request.Context()).Raw(`SELECT 1 FROM accounts WHERE username=$1 LIMIT 1`, payload.Username).Row().Scan(&exists); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "error_description": "username already exists"})
		return
	}
	userID := models.LegitID()
	hash, _ := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	dbWrite, err := s.GetIAMWriteDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("open db: %v", err)})
		return
	}
	if err := dbWrite.WithContext(c.Request.Context()).Exec(`INSERT INTO accounts (id, username, password_hash) VALUES ($1, $2, $3)`, userID, payload.Username, string(hash)).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": fmt.Sprintf("insert user: %v", err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user_id": userID})
}

// Swagger fragments for API paths
func (s *Server) swaggerAPILoginPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "IAM login and token issuance",
			"description": "Authenticates a user against the users table and issues access/refresh tokens. Client must authenticate using HTTP Basic.",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"username": map[string]interface{}{"type": "string"},
								"password": map[string]interface{}{"type": "string"},
							},
							"required": []string{"username", "password"},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Token response",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{
								"access_token":  map[string]interface{}{"type": "string"},
								"token_type":    map[string]interface{}{"type": "string"},
								"expires_in":    map[string]interface{}{"type": "integer"},
								"refresh_token": map[string]interface{}{"type": "string"},
								"scope":         map[string]interface{}{"type": "string"},
							}},
						},
					},
				},
				"401": map[string]interface{}{"description": "Unauthorized"},
				"400": map[string]interface{}{"description": "Invalid request"},
			},
			"security": []map[string]interface{}{{"basicAuth": []string{}}},
		},
	}
}

func (s *Server) swaggerRegisterUserPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "IAM registration",
			"description": "Registers a new user with username and password (bcrypt-hashed).",
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"type":       "object",
							"properties": map[string]interface{}{"username": map[string]interface{}{"type": "string"}, "password": map[string]interface{}{"type": "string"}},
							"required":   []string{"username", "password"},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"201": map[string]interface{}{"description": "IAM created", "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"user_id": map[string]interface{}{"type": "string", "description": "Hyphenless UUID string"}}}}}},
				"400": map[string]interface{}{"description": "Invalid request"},
				"409": map[string]interface{}{"description": "Username conflict"},
			},
		},
	}
}
