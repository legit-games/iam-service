package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-oauth2/oauth2/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// HandleAPILogin authenticates a user and issues access/refresh tokens via JSON API.
func (s *Server) HandleAPILogin(w http.ResponseWriter, r *http.Request) error {
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
	if strings.TrimSpace(payload.Username) == "" || strings.TrimSpace(payload.Password) == "" {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "username and password are required",
		})
	}

	dsn := strings.TrimSpace(os.Getenv("USER_DB_DSN"))
	if dsn == "" {
		w.WriteHeader(http.StatusNotImplemented)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "not_implemented",
			"error_description": "set USER_DB_DSN to enable login",
		})
	}
	// Open GORM connection (raw SQL only)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("open db: %v", err),
		})
	}

	var (
		uid  string
		hash string
	)
	// Raw query via GORM
	row := db.WithContext(r.Context()).Raw(`SELECT id, password_hash FROM accounts WHERE username=$1`, payload.Username).Row()
	if err := row.Scan(&uid, &hash); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "invalid username or password",
		})
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(payload.Password)) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "invalid username or password",
		})
	}

	clientID, clientSecret, _ := s.ClientInfoHandler(r)
	tgr := &oauth2.TokenGenerateRequest{ClientID: clientID, ClientSecret: clientSecret, UserID: uid, Request: r}
	ti, genErr := s.Manager.GenerateAccessToken(r.Context(), oauth2.PasswordCredentials, tgr)
	if genErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "server_error",
			"error_description": fmt.Sprintf("token generation: %v", genErr),
		})
	}
	return s.token(w, s.GetTokenData(ti), nil)
}
