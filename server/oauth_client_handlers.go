package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/errors"
)

// Client registration is no longer supported; respond with 501.

func (s *Server) HandleClientRegistrationRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return s.tokenError(w, errors.ErrInvalidRequest)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	return NotImplemented(w, "dynamic client registration is disabled")
}

// HandleClientRegistrationGin responds with 501 Not Implemented.
func (s *Server) HandleClientRegistrationGin(c *gin.Context) {
	NotImplementedGin(c, "dynamic client registration is disabled")
}
