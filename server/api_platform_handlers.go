package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/platforms"
	"github.com/go-oauth2/oauth2/v4/store"
)

// Platform ID validation regex (alphanumeric, 1-256 chars)
var platformIDRegex = regexp.MustCompile(`^[a-zA-Z0-9]{1,256}$`)

// Request ID validation regex (UUID4 without hyphens, 32 hex chars)
var requestIDRegex = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// HandleGetPlatformTokenGin retrieves a third-party platform token for a user.
// Route: GET /iam/v1/oauth/admin/namespaces/:ns/users/:userId/platforms/:platformId/platformToken
func (s *Server) HandleGetPlatformTokenGin(c *gin.Context) {
	// Step 1: Extract path parameters
	namespace := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	userID := strings.TrimSpace(c.Param("userId"))
	platformID := strings.ToLower(strings.TrimSpace(c.Param("platformId")))

	if namespace == "" || userID == "" || platformID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace, userId, and platformId are required",
		})
		return
	}

	// Get database connection
	db, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			c.JSON(http.StatusNotImplemented, gin.H{
				"error":             "not_implemented",
				"error_description": "database not configured",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to connect to database",
		})
		return
	}

	// Initialize stores
	platformUserStore := store.NewPlatformUserStore(db)
	accountGroup := platforms.NewAccountGroup()

	// Step 2: Resolve platform groups
	platformIDs := []string{platformID}
	tokenSourcePlatformID := platformID

	// If platformID is a group name, get all members
	if members := accountGroup.GetGroupMembers(platformID); len(members) != 0 {
		platformIDs = members
	}

	// If platformID is a member, get siblings and use group name for token
	if siblings := accountGroup.GetSiblingMembers(platformID); len(siblings) != 0 {
		platformIDs = siblings
		tokenSourcePlatformID = accountGroup.GetGroupName(platformID)
	}

	// Step 3: Handle game vs publisher namespace
	// For now, use the requested namespace directly
	// In a full implementation, this would resolve game namespace to publisher namespace
	publisherNamespace := namespace

	// Step 4: Query linked platform accounts
	var thirdPartyAccounts []models.PlatformUser
	for _, memberPlatformID := range platformIDs {
		accounts, err := platformUserStore.GetPlatformAccountsByPlatformID(
			c.Request.Context(), publisherNamespace, userID, memberPlatformID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "unable to query platform accounts",
			})
			return
		}
		thirdPartyAccounts = append(thirdPartyAccounts, accounts...)
	}

	if len(thirdPartyAccounts) == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "user_not_found",
			"error_description": "third party account not found",
		})
		return
	}

	// Step 5: Find linked platform info
	platformUserID, linkedNamespace, _ := getLinkedPlatformInfo(
		platformIDs, thirdPartyAccounts, userID, namespace)

	// Fallback to publisher namespace if game namespace has no link
	if platformUserID == "" && publisherNamespace != namespace {
		platformUserID, linkedNamespace, _ = getLinkedPlatformInfo(
			platformIDs, thirdPartyAccounts, userID, publisherNamespace)
	}

	if platformUserID == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "user_not_found",
			"error_description": "third party account not found",
		})
		return
	}

	// Step 6: Load token from cache
	// For this implementation, we'll try to load from Redis/Valkey cache
	// In a full implementation, this would also handle token refresh

	// Get Valkey address from config
	valkeyAddr := GetConfig().ValkeyAddr()
	if valkeyAddr == "" {
		// If no Redis/Valkey configured, return the refresh token info
		// In production, this should attempt to refresh the token
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "platform_token_not_found",
			"error_description": "platform token cache not configured",
		})
		return
	}

	platformTokenStore, err := store.NewPlatformTokenStore(valkeyAddr, "iam:")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to connect to token cache",
		})
		return
	}

	platformToken, err := platformTokenStore.Load(
		c.Request.Context(), linkedNamespace, tokenSourcePlatformID, platformUserID)
	if err != nil {
		if err == store.ErrPlatformTokenNotFound {
			// Token not in cache - in production, try to refresh using stored refresh token
			// For now, return not found
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "platform_token_not_found",
				"error_description": "third party token not found or expired",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to load platform token",
		})
		return
	}

	// Return the token
	c.JSON(http.StatusOK, models.TokenThirdPartyResponse{
		PlatformToken: platformToken.ThirdPartyToken,
		SandBoxID:     platformToken.SandboxID,
	})
}

// getLinkedPlatformInfo searches for a matching platform account.
func getLinkedPlatformInfo(platformIDs []string, accounts []models.PlatformUser,
	userID, namespace string) (platformUserID, linkedNamespace, refreshToken string) {
	for _, memberPlatformID := range platformIDs {
		for _, account := range accounts {
			if account.PlatformID == memberPlatformID &&
				account.UserID == userID &&
				account.Namespace == namespace {
				return account.PlatformUserID, account.Namespace, account.RefreshToken
			}
		}
	}
	return "", "", ""
}

// HandleListPlatformAccountsGin lists all platform accounts for a user.
// Route: GET /iam/v3/oauth/admin/namespaces/:ns/users/:userId/platforms
func (s *Server) HandleListPlatformAccountsGin(c *gin.Context) {
	namespace := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	userID := strings.TrimSpace(c.Param("userId"))

	if namespace == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace and userId are required",
		})
		return
	}

	db, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			c.JSON(http.StatusNotImplemented, gin.H{
				"error":             "not_implemented",
				"error_description": "database not configured",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to connect to database",
		})
		return
	}

	platformUserStore := store.NewPlatformUserStore(db)
	accounts, err := platformUserStore.ListPlatformAccountsByUser(c.Request.Context(), namespace, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to query platform accounts",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"platforms": accounts})
}

// HandlePlatformAuthorizeGin initiates OAuth authorization flow with third-party platforms.
// Route: GET /iam/v1/oauth/platforms/:platformId/authorize
// This endpoint:
// 1. Validates the authorization request (stored in Redis)
// 2. Retrieves platform client configuration
// 3. Constructs the platform-specific OAuth authorization URL
// 4. Redirects the user to the third-party platform's login page
func (s *Server) HandlePlatformAuthorizeGin(c *gin.Context) {
	// Step 1: Extract and validate parameters
	platformID := strings.ToLower(strings.TrimSpace(c.Param("platformId")))
	requestID := strings.TrimSpace(c.Query("request_id"))
	clientID := strings.TrimSpace(c.Query("client_id"))
	redirectURI := strings.TrimSpace(c.Query("redirect_uri"))

	// Build error redirect URL helper
	errorRedirect := func(errCode, errDesc string) {
		// If we have client_id and redirect_uri, redirect there with error
		if clientID != "" && redirectURI != "" {
			parsed, err := url.Parse(redirectURI)
			if err == nil {
				q := parsed.Query()
				q.Set("error", errCode)
				q.Set("error_description", errDesc)
				parsed.RawQuery = q.Encode()
				c.Redirect(http.StatusFound, parsed.String())
				return
			}
		}
		// Otherwise return JSON error
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errCode,
			"error_description": errDesc,
		})
	}

	// Validate platformId
	if platformID == "" || !platformIDRegex.MatchString(platformID) {
		errorRedirect("invalid_request", "invalid or missing platform_id")
		return
	}

	// Validate request_id
	if requestID == "" {
		errorRedirect("invalid_request", "request_id parameter is required")
		return
	}
	if !requestIDRegex.MatchString(requestID) {
		errorRedirect("invalid_request", "invalid request_id format")
		return
	}

	// Step 2: Load authorization request from Redis
	valkeyAddr := GetConfig().ValkeyAddr()
	if valkeyAddr == "" {
		errorRedirect("server_error", "authorization request storage not configured")
		return
	}

	authRequestStore, err := store.NewAuthorizationRequestStore(valkeyAddr, GetConfig().ValkeyPrefix())
	if err != nil {
		errorRedirect("server_error", "unable to connect to authorization request storage")
		return
	}

	authRequest, err := authRequestStore.Load(c.Request.Context(), requestID)
	if err != nil {
		if err == store.ErrAuthorizationRequestNotFound {
			errorRedirect("invalid_request", "authorization request not found or expired")
			return
		}
		errorRedirect("server_error", "unable to load authorization request")
		return
	}

	// Step 3: Get platform client configuration from database
	db, err := s.GetIAMReadDB()
	if err != nil {
		errorRedirect("server_error", "database not available")
		return
	}

	platformClientStore := store.NewPlatformClientStore(db)
	platformClient, err := platformClientStore.GetByNamespaceAndPlatform(
		c.Request.Context(), authRequest.Namespace, platformID)
	if err != nil {
		errorRedirect("server_error", "unable to query platform configuration")
		return
	}
	if platformClient == nil {
		errorRedirect("invalid_request", "platform not configured for this namespace")
		return
	}

	// Step 4: Get platform-specific handler and build authorization URL
	handlerRegistry := platforms.NewAuthorizeHandlerRegistry()
	handler := handlerRegistry.Get(platformID)

	// For generic OIDC platforms, use the generic handler
	if platformClient.GenericOauthFlow {
		handler = handlerRegistry.Get("generic")
	}

	// Determine base URI for callback
	baseURI := s.getBaseURI(c.Request)

	authorizeURL, err := handler.BuildAuthorizeURL(baseURI, platformClient, requestID)
	if err != nil {
		errorRedirect("server_error", "unable to build authorization URL: "+err.Error())
		return
	}

	// Step 5: Redirect to platform's authorization page
	c.Redirect(http.StatusFound, authorizeURL)
}

// getBaseURI extracts the base URI from the request for building callback URLs.
func (s *Server) getBaseURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		// Check X-Forwarded-Proto header
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}

	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	return scheme + "://" + host
}

// HandlePlatformAuthenticateGin handles the callback from third-party platforms.
// Route: GET /iam/v1/platforms/:platformId/authenticate
// This endpoint:
// 1. Receives the authorization code from the platform
// 2. Exchanges it for access tokens
// 3. Creates or links the user account
// 4. Redirects back to the original client application
func (s *Server) HandlePlatformAuthenticateGin(c *gin.Context) {
	platformID := strings.ToLower(strings.TrimSpace(c.Param("platformId")))
	code := c.Query("code")
	state := c.Query("state") // This is the request_id

	// For error responses from the platform
	if errCode := c.Query("error"); errCode != "" {
		errDesc := c.Query("error_description")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errCode,
			"error_description": errDesc,
		})
		return
	}

	if platformID == "" || code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "missing required parameters",
		})
		return
	}

	// Load authorization request to get original client info
	valkeyAddr := GetConfig().ValkeyAddr()
	if valkeyAddr == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "authorization request storage not configured",
		})
		return
	}

	authRequestStore, err := store.NewAuthorizationRequestStore(valkeyAddr, GetConfig().ValkeyPrefix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to connect to storage",
		})
		return
	}

	authRequest, err := authRequestStore.Load(c.Request.Context(), state)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "authorization request not found or expired",
		})
		return
	}

	// TODO: Exchange code for tokens with the platform
	// TODO: Get user info from platform
	// TODO: Create or link user account
	// TODO: Generate IAM tokens
	// TODO: Redirect to client's redirect_uri with authorization code

	// For now, return a placeholder response
	c.JSON(http.StatusOK, gin.H{
		"message":     "platform authentication callback received",
		"platform_id": platformID,
		"request_id":  state,
		"namespace":   authRequest.Namespace,
		"client_id":   authRequest.ClientID,
		"redirect_uri": authRequest.RedirectURI,
		"note":        "token exchange not yet implemented",
	})
}
