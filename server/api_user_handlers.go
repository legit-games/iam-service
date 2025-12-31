package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-oauth2/oauth2/v4/models"
	_ "github.com/lib/pq"
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

	driver := strings.TrimSpace(os.Getenv("USER_DB_DRIVER"))
	if driver == "" {
		driver = "postgres"
	}
	dsn := strings.TrimSpace(os.Getenv("USER_DB_DSN"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("MIGRATE_DSN"))
	}
	if dsn == "" {
		w.WriteHeader(http.StatusNotImplemented)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "not_implemented",
			"error_description": "set USER_DB_DRIVER and USER_DB_DSN (or MIGRATE_DSN) to enable user registration",
		})
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("open db: %v", err),
		})
	}
	defer db.Close()

	var exists int
	qExists := `SELECT 1 FROM users WHERE username=$1 LIMIT 1`
	if driver == "sqlite" {
		qExists = `SELECT 1 FROM users WHERE username=? LIMIT 1`
	}
	if err := db.QueryRowContext(r.Context(), qExists, payload.Username).Scan(&exists); err == nil {
		w.WriteHeader(http.StatusConflict)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "conflict",
			"error_description": "username already exists",
		})
	}

	userID := models.LegitID()
	hash, _ := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	qIns := `INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)`
	args := []interface{}{userID, payload.Username, string(hash)}
	if driver == "sqlite" {
		qIns = `INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)`
	}
	if _, err := db.ExecContext(r.Context(), qIns, args...); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("insert user: %v", err),
		})
	}

	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(map[string]interface{}{"user_id": userID})
}

// Swagger fragments for API paths
func (s *Server) swaggerAPILoginPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "User login and token issuance",
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
			"summary":     "User registration",
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
				"201": map[string]interface{}{"description": "User created", "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"user_id": map[string]interface{}{"type": "string", "description": "Hyphenless UUID string"}}}}}},
				"400": map[string]interface{}{"description": "Invalid request"},
				"409": map[string]interface{}{"description": "Username conflict"},
			},
		},
	}
}
