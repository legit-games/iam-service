package server

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/email"
	"github.com/go-oauth2/oauth2/v4/store"
)

// EmailProviderResponse represents an email provider in API responses
type EmailProviderResponse struct {
	ID             string          `json:"id"`
	NamespaceID    *string         `json:"namespace_id,omitempty"`
	Name           string          `json:"name"`
	ProviderType   string          `json:"provider_type"`
	IsActive       bool            `json:"is_active"`
	IsDefault      bool            `json:"is_default"`
	FromAddress    string          `json:"from_address"`
	FromName       string          `json:"from_name"`
	ReplyToAddress string          `json:"reply_to_address,omitempty"`
	Config         json.RawMessage `json:"config,omitempty"`
	AppName        string          `json:"app_name"`
	SupportEmail   string          `json:"support_email,omitempty"`
	Description    string          `json:"description,omitempty"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
}

// MaskSecrets masks sensitive fields in the config
func maskProviderConfig(providerType string, config json.RawMessage) json.RawMessage {
	switch providerType {
	case "smtp":
		var cfg email.SMTPConfig
		if err := json.Unmarshal(config, &cfg); err == nil {
			if cfg.Password != "" {
				cfg.Password = "********"
			}
			masked, _ := json.Marshal(cfg)
			return masked
		}
	case "sendgrid":
		var cfg email.SendGridConfig
		if err := json.Unmarshal(config, &cfg); err == nil {
			if cfg.APIKey != "" {
				cfg.APIKey = "********"
			}
			masked, _ := json.Marshal(cfg)
			return masked
		}
	case "aws_ses":
		var cfg email.AWSSESConfig
		if err := json.Unmarshal(config, &cfg); err == nil {
			if cfg.SecretAccessKey != "" {
				cfg.SecretAccessKey = "********"
			}
			masked, _ := json.Marshal(cfg)
			return masked
		}
	case "mailgun":
		var cfg email.MailgunConfig
		if err := json.Unmarshal(config, &cfg); err == nil {
			if cfg.APIKey != "" {
				cfg.APIKey = "********"
			}
			masked, _ := json.Marshal(cfg)
			return masked
		}
	case "mailchimp":
		var cfg email.MailchimpConfig
		if err := json.Unmarshal(config, &cfg); err == nil {
			if cfg.APIKey != "" {
				cfg.APIKey = "********"
			}
			masked, _ := json.Marshal(cfg)
			return masked
		}
	}
	return config
}

func toProviderResponse(p *store.EmailProvider, maskSecrets bool) EmailProviderResponse {
	config := p.Config
	if maskSecrets {
		config = maskProviderConfig(p.ProviderType, p.Config)
	}

	return EmailProviderResponse{
		ID:             p.ID,
		NamespaceID:    p.NamespaceID,
		Name:           p.Name,
		ProviderType:   p.ProviderType,
		IsActive:       p.IsActive,
		IsDefault:      p.IsDefault,
		FromAddress:    p.FromAddress,
		FromName:       p.FromName,
		ReplyToAddress: p.ReplyToAddress,
		Config:         config,
		AppName:        p.AppName,
		SupportEmail:   p.SupportEmail,
		Description:    p.Description,
		CreatedAt:      p.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:      p.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// HandleListEmailProvidersGin lists all email providers
// GET /iam/v1/admin/email-providers
func (s *Server) HandleListEmailProvidersGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	ctx := c.Request.Context()
	providers, err := s.emailProviderStore.List(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to list email providers",
		})
		return
	}

	response := make([]EmailProviderResponse, len(providers))
	for i, p := range providers {
		response[i] = toProviderResponse(&p, true)
	}

	c.JSON(http.StatusOK, gin.H{
		"providers": response,
	})
}

// HandleGetEmailProviderGin gets a specific email provider
// GET /iam/v1/admin/email-providers/:id
func (s *Server) HandleGetEmailProviderGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	provider, err := s.emailProviderStore.GetByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found",
		})
		return
	}

	c.JSON(http.StatusOK, toProviderResponse(provider, true))
}

// HandleCreateEmailProviderGin creates a new email provider
// POST /iam/v1/admin/email-providers
func (s *Server) HandleCreateEmailProviderGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	var req store.CreateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	provider := &store.EmailProvider{
		Name:           req.Name,
		ProviderType:   req.ProviderType,
		FromAddress:    req.FromAddress,
		FromName:       req.FromName,
		ReplyToAddress: req.ReplyToAddress,
		Config:         req.Config,
		AppName:        req.AppName,
		SupportEmail:   req.SupportEmail,
		Description:    req.Description,
		IsActive:       req.IsActive,
	}

	if err := s.emailProviderStore.Create(ctx, provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to create email provider",
		})
		return
	}

	// Set as default if requested
	if req.SetAsDefault {
		if err := s.emailProviderStore.SetDefault(ctx, provider.ID); err != nil {
			// Log but don't fail
		}
		provider.IsDefault = true
	}

	c.JSON(http.StatusCreated, toProviderResponse(provider, true))
}

// HandleUpdateEmailProviderGin updates an email provider
// PUT /iam/v1/admin/email-providers/:id
func (s *Server) HandleUpdateEmailProviderGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	provider, err := s.emailProviderStore.GetByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found",
		})
		return
	}

	var req store.UpdateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Update fields if provided
	if req.Name != "" {
		provider.Name = req.Name
	}
	if req.FromAddress != "" {
		provider.FromAddress = req.FromAddress
	}
	if req.FromName != "" {
		provider.FromName = req.FromName
	}
	if req.ReplyToAddress != "" {
		provider.ReplyToAddress = req.ReplyToAddress
	}
	if req.Config != nil {
		// Merge config: keep existing secrets if new ones are masked
		provider.Config = mergeProviderConfig(provider.ProviderType, provider.Config, req.Config)
	}
	if req.AppName != "" {
		provider.AppName = req.AppName
	}
	if req.SupportEmail != "" {
		provider.SupportEmail = req.SupportEmail
	}
	if req.Description != "" {
		provider.Description = req.Description
	}
	if req.IsActive != nil {
		provider.IsActive = *req.IsActive
	}

	if err := s.emailProviderStore.Update(ctx, provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to update email provider",
		})
		return
	}

	c.JSON(http.StatusOK, toProviderResponse(provider, true))
}

// HandleDeleteEmailProviderGin deletes an email provider
// DELETE /iam/v1/admin/email-providers/:id
func (s *Server) HandleDeleteEmailProviderGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	// Check if provider exists
	provider, err := s.emailProviderStore.GetByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found",
		})
		return
	}

	// Prevent deleting the only default provider
	if provider.IsDefault {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Cannot delete the default provider. Set another provider as default first.",
		})
		return
	}

	if err := s.emailProviderStore.Delete(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to delete email provider",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Email provider deleted successfully",
	})
}

// HandleSetDefaultEmailProviderGin sets a provider as default
// POST /iam/v1/admin/email-providers/:id/set-default
func (s *Server) HandleSetDefaultEmailProviderGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	// Check if provider exists
	if _, err := s.emailProviderStore.GetByID(ctx, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found",
		})
		return
	}

	if err := s.emailProviderStore.SetDefault(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to set default provider",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Default email provider updated successfully",
	})
}

// HandleTestEmailProviderGin tests an email provider by sending a test email
// POST /iam/v1/admin/email-providers/:id/test
func (s *Server) HandleTestEmailProviderGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	id := c.Param("id")

	var req struct {
		ToEmail string `json:"to_email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Valid email address is required",
		})
		return
	}

	ctx := c.Request.Context()

	// Get sender for this specific provider
	sender, err := s.emailProviderStore.GetSenderByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": err.Error(),
		})
		return
	}

	// Get provider for app name
	provider, _ := s.emailProviderStore.GetByID(ctx, id)

	// Send test email
	testData := email.PasswordResetEmailData{
		To:           req.ToEmail,
		Username:     "Test User",
		Code:         "123456",
		ExpiresInMin: 60,
		AppName:      provider.AppName,
		SupportEmail: provider.SupportEmail,
	}

	if err := sender.SendPasswordReset(ctx, testData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "email_failed",
			"error_description": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Test email sent to " + req.ToEmail,
	})
}

// HandleGetSupportedProvidersGin returns list of supported provider types
// GET /iam/v1/admin/email-providers/types
func (s *Server) HandleGetSupportedProvidersGin(c *gin.Context) {
	providers := email.SupportedProviders()

	// Add config schema for each provider
	type ProviderTypeInfo struct {
		Type         string                 `json:"type"`
		Name         string                 `json:"name"`
		Description  string                 `json:"description"`
		ConfigSchema map[string]interface{} `json:"config_schema"`
	}

	result := make([]ProviderTypeInfo, len(providers))
	for i, p := range providers {
		result[i] = ProviderTypeInfo{
			Type:         string(p.Type),
			Name:         p.Name,
			Description:  p.Description,
			ConfigSchema: getConfigSchema(string(p.Type)),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"provider_types": result,
	})
}

// getConfigSchema returns the JSON schema for a provider type's config
func getConfigSchema(providerType string) map[string]interface{} {
	schemas := map[string]map[string]interface{}{
		"console": {},
		"smtp": {
			"host":        map[string]interface{}{"type": "string", "required": true, "label": "SMTP Host"},
			"port":        map[string]interface{}{"type": "number", "default": 587, "label": "SMTP Port"},
			"username":    map[string]interface{}{"type": "string", "label": "Username"},
			"password":    map[string]interface{}{"type": "password", "label": "Password"},
			"use_tls":     map[string]interface{}{"type": "boolean", "default": true, "label": "Use STARTTLS"},
			"use_ssl":     map[string]interface{}{"type": "boolean", "default": false, "label": "Use SSL"},
			"skip_verify": map[string]interface{}{"type": "boolean", "default": false, "label": "Skip Certificate Verification"},
		},
		"sendgrid": {
			"api_key": map[string]interface{}{"type": "password", "required": true, "label": "API Key"},
		},
		"aws_ses": {
			"region":            map[string]interface{}{"type": "string", "required": true, "label": "AWS Region"},
			"access_key_id":     map[string]interface{}{"type": "string", "label": "Access Key ID"},
			"secret_access_key": map[string]interface{}{"type": "password", "label": "Secret Access Key"},
			"use_iam_role":      map[string]interface{}{"type": "boolean", "default": false, "label": "Use IAM Role"},
		},
		"mailgun": {
			"domain":   map[string]interface{}{"type": "string", "required": true, "label": "Mailgun Domain"},
			"api_key":  map[string]interface{}{"type": "password", "required": true, "label": "API Key"},
			"api_base": map[string]interface{}{"type": "string", "default": "https://api.mailgun.net/v3", "label": "API Base URL"},
		},
		"mailchimp": {
			"api_key": map[string]interface{}{"type": "password", "required": true, "label": "Mandrill API Key"},
		},
	}

	if schema, ok := schemas[providerType]; ok {
		return schema
	}
	return map[string]interface{}{}
}

// mergeProviderConfig merges new config with existing, preserving secrets if masked
func mergeProviderConfig(providerType string, existing, new json.RawMessage) json.RawMessage {
	// If new config contains masked values, keep existing secrets
	switch providerType {
	case "smtp":
		var existingCfg, newCfg email.SMTPConfig
		json.Unmarshal(existing, &existingCfg)
		json.Unmarshal(new, &newCfg)
		if newCfg.Password == "********" || newCfg.Password == "" {
			newCfg.Password = existingCfg.Password
		}
		merged, _ := json.Marshal(newCfg)
		return merged
	case "sendgrid":
		var existingCfg, newCfg email.SendGridConfig
		json.Unmarshal(existing, &existingCfg)
		json.Unmarshal(new, &newCfg)
		if newCfg.APIKey == "********" || newCfg.APIKey == "" {
			newCfg.APIKey = existingCfg.APIKey
		}
		merged, _ := json.Marshal(newCfg)
		return merged
	case "aws_ses":
		var existingCfg, newCfg email.AWSSESConfig
		json.Unmarshal(existing, &existingCfg)
		json.Unmarshal(new, &newCfg)
		if newCfg.SecretAccessKey == "********" || newCfg.SecretAccessKey == "" {
			newCfg.SecretAccessKey = existingCfg.SecretAccessKey
		}
		merged, _ := json.Marshal(newCfg)
		return merged
	case "mailgun":
		var existingCfg, newCfg email.MailgunConfig
		json.Unmarshal(existing, &existingCfg)
		json.Unmarshal(new, &newCfg)
		if newCfg.APIKey == "********" || newCfg.APIKey == "" {
			newCfg.APIKey = existingCfg.APIKey
		}
		merged, _ := json.Marshal(newCfg)
		return merged
	case "mailchimp":
		var existingCfg, newCfg email.MailchimpConfig
		json.Unmarshal(existing, &existingCfg)
		json.Unmarshal(new, &newCfg)
		if newCfg.APIKey == "********" || newCfg.APIKey == "" {
			newCfg.APIKey = existingCfg.APIKey
		}
		merged, _ := json.Marshal(newCfg)
		return merged
	}
	return new
}

// reinitializeEmailSenderFromProviders is no longer needed as email senders are namespace-scoped
// Each namespace should have its own email provider configuration

// ============================================================================
// Namespace-Scoped Email Provider Handlers
// ============================================================================

// HandleListEmailProvidersByNamespaceGin lists email providers for a specific namespace
// GET /iam/v1/admin/namespaces/:ns/email-providers
func (s *Server) HandleListEmailProvidersByNamespaceGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	namespaceID := c.Param("ns")
	if namespaceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace is required",
		})
		return
	}

	ctx := c.Request.Context()
	providers, err := s.emailProviderStore.ListByNamespace(ctx, namespaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to list email providers",
		})
		return
	}

	response := make([]EmailProviderResponse, len(providers))
	for i, p := range providers {
		response[i] = toProviderResponse(&p, true)
	}

	c.JSON(http.StatusOK, gin.H{
		"providers":    response,
		"namespace_id": namespaceID,
	})
}

// HandleGetEmailProviderByNamespaceGin gets a specific email provider within a namespace
// GET /iam/v1/admin/namespaces/:ns/email-providers/:id
func (s *Server) HandleGetEmailProviderByNamespaceGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	namespaceID := c.Param("ns")
	id := c.Param("id")
	ctx := c.Request.Context()

	provider, err := s.emailProviderStore.GetByIDAndNamespace(ctx, id, namespaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found in this namespace",
		})
		return
	}

	c.JSON(http.StatusOK, toProviderResponse(provider, true))
}

// HandleCreateEmailProviderByNamespaceGin creates a new email provider within a namespace
// POST /iam/v1/admin/namespaces/:ns/email-providers
func (s *Server) HandleCreateEmailProviderByNamespaceGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	namespaceID := c.Param("ns")
	if namespaceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace is required",
		})
		return
	}

	var req store.CreateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	provider := &store.EmailProvider{
		NamespaceID:    &namespaceID,
		Name:           req.Name,
		ProviderType:   req.ProviderType,
		FromAddress:    req.FromAddress,
		FromName:       req.FromName,
		ReplyToAddress: req.ReplyToAddress,
		Config:         req.Config,
		AppName:        req.AppName,
		SupportEmail:   req.SupportEmail,
		Description:    req.Description,
		IsActive:       req.IsActive,
	}

	if err := s.emailProviderStore.Create(ctx, provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to create email provider",
		})
		return
	}

	// Set as default if requested
	if req.SetAsDefault {
		if err := s.emailProviderStore.SetDefault(ctx, provider.ID); err != nil {
			// Log but don't fail
		}
		provider.IsDefault = true
	}

	c.JSON(http.StatusCreated, toProviderResponse(provider, true))
}

// HandleUpdateEmailProviderByNamespaceGin updates an email provider within a namespace
// PUT /iam/v1/admin/namespaces/:ns/email-providers/:id
func (s *Server) HandleUpdateEmailProviderByNamespaceGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	namespaceID := c.Param("ns")
	id := c.Param("id")
	ctx := c.Request.Context()

	provider, err := s.emailProviderStore.GetByIDAndNamespace(ctx, id, namespaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found in this namespace",
		})
		return
	}

	var req store.UpdateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Update fields if provided
	if req.Name != "" {
		provider.Name = req.Name
	}
	if req.FromAddress != "" {
		provider.FromAddress = req.FromAddress
	}
	if req.FromName != "" {
		provider.FromName = req.FromName
	}
	if req.ReplyToAddress != "" {
		provider.ReplyToAddress = req.ReplyToAddress
	}
	if req.Config != nil {
		provider.Config = mergeProviderConfig(provider.ProviderType, provider.Config, req.Config)
	}
	if req.AppName != "" {
		provider.AppName = req.AppName
	}
	if req.SupportEmail != "" {
		provider.SupportEmail = req.SupportEmail
	}
	if req.Description != "" {
		provider.Description = req.Description
	}
	if req.IsActive != nil {
		provider.IsActive = *req.IsActive
	}

	if err := s.emailProviderStore.Update(ctx, provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to update email provider",
		})
		return
	}

	c.JSON(http.StatusOK, toProviderResponse(provider, true))
}

// HandleDeleteEmailProviderByNamespaceGin deletes an email provider within a namespace
// DELETE /iam/v1/admin/namespaces/:ns/email-providers/:id
func (s *Server) HandleDeleteEmailProviderByNamespaceGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	namespaceID := c.Param("ns")
	id := c.Param("id")
	ctx := c.Request.Context()

	// Check if provider exists in this namespace
	provider, err := s.emailProviderStore.GetByIDAndNamespace(ctx, id, namespaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found in this namespace",
		})
		return
	}

	// Prevent deleting the default provider
	if provider.IsDefault {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Cannot delete the default provider. Set another provider as default first.",
		})
		return
	}

	if err := s.emailProviderStore.DeleteByIDAndNamespace(ctx, id, namespaceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to delete email provider",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Email provider deleted successfully",
	})
}

// HandleSetDefaultEmailProviderByNamespaceGin sets a provider as default within a namespace
// POST /iam/v1/admin/namespaces/:ns/email-providers/:id/set-default
func (s *Server) HandleSetDefaultEmailProviderByNamespaceGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	namespaceID := c.Param("ns")
	id := c.Param("id")
	ctx := c.Request.Context()

	// Check if provider exists in this namespace
	if _, err := s.emailProviderStore.GetByIDAndNamespace(ctx, id, namespaceID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found in this namespace",
		})
		return
	}

	if err := s.emailProviderStore.SetDefault(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": "Failed to set default provider",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Default email provider updated successfully",
	})
}

// HandleTestEmailProviderByNamespaceGin tests an email provider within a namespace
// POST /iam/v1/admin/namespaces/:ns/email-providers/:id/test
func (s *Server) HandleTestEmailProviderByNamespaceGin(c *gin.Context) {
	if s.emailProviderStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "service_unavailable",
			"error_description": "Email provider store not configured",
		})
		return
	}

	namespaceID := c.Param("ns")
	id := c.Param("id")

	var req struct {
		ToEmail string `json:"to_email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Valid email address is required",
		})
		return
	}

	ctx := c.Request.Context()

	// Verify provider exists in namespace
	provider, err := s.emailProviderStore.GetByIDAndNamespace(ctx, id, namespaceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "Email provider not found in this namespace",
		})
		return
	}

	// Get sender for this specific provider
	sender, err := s.emailProviderStore.GetSenderByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_error",
			"error_description": err.Error(),
		})
		return
	}

	// Send test email
	testData := email.PasswordResetEmailData{
		To:           req.ToEmail,
		Username:     "Test User",
		Code:         "123456",
		ExpiresInMin: 60,
		AppName:      provider.AppName,
		SupportEmail: provider.SupportEmail,
	}

	if err := sender.SendPasswordReset(ctx, testData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "email_failed",
			"error_description": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Test email sent to " + req.ToEmail,
	})
}
