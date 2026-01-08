package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/platforms"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-oauth2/oauth2/v4/dto"
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
		"message":      "platform authentication callback received",
		"platform_id":  platformID,
		"request_id":   state,
		"namespace":    authRequest.Namespace,
		"client_id":    authRequest.ClientID,
		"redirect_uri": authRequest.RedirectURI,
		"note":         "token exchange not yet implemented",
	})
}

// Device ID validation regex (alphanumeric/dash/underscore, no whitespace, 1-256 chars)
var deviceIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,256}$`)

// HandlePlatformTokenGin handles platform token authentication.
// Route: POST /iam/v1/oauth/platforms/:platformId/token
// This endpoint:
// 1. Authenticates the client via Basic Auth
// 2. Verifies the platform token or device_id
// 3. Links or creates a user account
// 4. Returns IAM access tokens
func (s *Server) HandlePlatformTokenGin(c *gin.Context) {
	// Step 1: Extract platformId from path
	platformID := strings.ToLower(strings.TrimSpace(c.Param("platformId")))
	if platformID == "" || !platformIDRegex.MatchString(platformID) {
		c.JSON(http.StatusBadRequest, models.PlatformTokenErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid or missing platform_id",
		})
		return
	}

	// Step 2: Validate client credentials (Basic Auth)
	clientID, clientSecret, err := ClientBasicHandler(c.Request)
	if err != nil {
		c.Header("WWW-Authenticate", `Basic realm="oauth2"`)
		c.JSON(http.StatusUnauthorized, models.PlatformTokenErrorResponse{
			Error:            "unauthorized_client",
			ErrorDescription: "invalid client credentials",
		})
		return
	}

	// Get client info from database
	db, err := s.GetIAMReadDB()
	if err != nil {
		if err == ErrUserDBDSNNotSet {
			c.JSON(http.StatusNotImplemented, models.PlatformTokenErrorResponse{
				Error:            "not_implemented",
				ErrorDescription: "database not configured",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, models.PlatformTokenErrorResponse{
			Error:            "server_error",
			ErrorDescription: "unable to connect to database",
		})
		return
	}

	// Validate client exists and secret matches
	clientStore := s.getDBClientStore()
	clientInfo, err := clientStore.GetByID(c.Request.Context(), clientID)
	if err != nil || clientInfo == nil {
		c.JSON(http.StatusUnauthorized, models.PlatformTokenErrorResponse{
			Error:            "unauthorized_client",
			ErrorDescription: "invalid client credentials",
		})
		return
	}
	if clientInfo.GetSecret() != clientSecret {
		c.JSON(http.StatusUnauthorized, models.PlatformTokenErrorResponse{
			Error:            "unauthorized_client",
			ErrorDescription: "invalid client credentials",
		})
		return
	}

	// Get namespace from client
	namespace := ""
	if ns, ok := clientInfo.(interface{ GetNamespace() string }); ok {
		namespace = ns.GetNamespace()
	}
	if namespace == "" {
		namespace = "DEFAULT"
	}

	// Step 3: Parse form body
	var req models.PlatformTokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.PlatformTokenErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid request body",
		})
		return
	}

	// Validate: either platform_token OR device_id must be provided (mutually exclusive)
	hasPlatformToken := strings.TrimSpace(req.PlatformToken) != ""
	hasDeviceID := strings.TrimSpace(req.DeviceID) != ""

	if !hasPlatformToken && !hasDeviceID {
		c.JSON(http.StatusBadRequest, models.PlatformTokenErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing required parameter: platform_token or device_id",
		})
		return
	}

	// Validate device_id format if provided
	if hasDeviceID {
		deviceID := strings.TrimSpace(req.DeviceID)
		if !deviceIDRegex.MatchString(deviceID) || hasWhitespace(deviceID) {
			c.JSON(http.StatusBadRequest, models.PlatformTokenErrorResponse{
				Error:            "invalid_request",
				ErrorDescription: "invalid device_id format",
			})
			return
		}
	}

	// Step 4: Get platform client configuration
	platformClientStore := store.NewPlatformClientStore(db)
	platformClient, err := platformClientStore.GetByNamespaceAndPlatform(c.Request.Context(), namespace, platformID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.PlatformTokenErrorResponse{
			Error:            "server_error",
			ErrorDescription: "unable to query platform configuration",
		})
		return
	}

	// For device-based platforms, platform client config is optional
	isDevicePlatform := platformID == "device" || platformID == "android" || platformID == "ios"
	if platformClient == nil && !isDevicePlatform {
		c.JSON(http.StatusBadRequest, models.PlatformTokenErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "platform not configured for this namespace",
			PlatformID:       platformID,
		})
		return
	}

	// Step 5: Verify platform token or handle device_id
	var platformUserInfo *platforms.PlatformUserInfo

	if hasDeviceID {
		// Device-based authentication - use device_id directly
		platformUserInfo = &platforms.PlatformUserInfo{
			PlatformUserID: strings.TrimSpace(req.DeviceID),
			DisplayName:    "Device User",
		}
	} else {
		// Platform token verification
		verifierRegistry := platforms.NewTokenVerifierRegistry()
		verifier := verifierRegistry.Get(platformID)

		// Use generic verifier for platforms with generic OAuth flow
		if platformClient != nil && platformClient.GenericOauthFlow {
			verifier = verifierRegistry.Get("generic")
		}

		platformUserInfo, err = verifier.VerifyToken(c.Request.Context(), platformClient, req.PlatformToken)
		if err != nil {
			switch err {
			case platforms.ErrInvalidPlatformToken:
				c.JSON(http.StatusUnauthorized, models.PlatformTokenErrorResponse{
					Error:            "invalid_grant",
					ErrorDescription: "invalid platform token",
				})
			case platforms.ErrPlatformUnavailable:
				c.JSON(http.StatusServiceUnavailable, models.PlatformTokenErrorResponse{
					Error:            "temporarily_unavailable",
					ErrorDescription: "platform service is temporarily unavailable",
				})
			case platforms.ErrTokenExpired:
				c.JSON(http.StatusUnauthorized, models.PlatformTokenErrorResponse{
					Error:            "invalid_grant",
					ErrorDescription: "platform token expired",
				})
			default:
				c.JSON(http.StatusUnauthorized, models.PlatformTokenErrorResponse{
					Error:            "invalid_grant",
					ErrorDescription: "platform token verification failed",
				})
			}
			return
		}
	}

	// Step 6: Check if platform account is already linked
	platformUserStore := store.NewPlatformUserStore(db)
	linkedAccount, err := platformUserStore.GetPlatformAccountByPlatformUserID(
		c.Request.Context(), namespace, platformID, platformUserInfo.PlatformUserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.PlatformTokenErrorResponse{
			Error:            "server_error",
			ErrorDescription: "unable to query platform account",
		})
		return
	}

	var userID string

	if linkedAccount != nil {
		// Account is already linked
		userID = linkedAccount.UserID
	} else {
		// Account not linked
		if !req.GetCreateHeadless() {
			// Return not_linked error with linking token
			linkingToken := models.LegitID()
			c.JSON(http.StatusUnauthorized, models.PlatformTokenErrorResponse{
				Error:            "not_linked",
				ErrorDescription: "platform account not linked with Justice account",
				PlatformID:       platformID,
				LinkingToken:     linkingToken,
				ClientID:         clientID,
			})
			return
		}

		// Create headless account
		userStore := store.NewUserStore(db)
		accountID := models.LegitID()
		err = userStore.CreateHeadlessAccount(c.Request.Context(), accountID, namespace, platformID, platformUserInfo.PlatformUserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.PlatformTokenErrorResponse{
				Error:            "server_error",
				ErrorDescription: "unable to create account",
			})
			return
		}

		// Create platform user link
		platformUser := &models.PlatformUser{
			UserID:         accountID,
			Namespace:      namespace,
			PlatformID:     platformID,
			PlatformUserID: platformUserInfo.PlatformUserID,
			DisplayName:    platformUserInfo.DisplayName,
			EmailAddress:   platformUserInfo.Email,
			AvatarURL:      platformUserInfo.AvatarURL,
		}
		if err := platformUserStore.CreatePlatformAccount(c.Request.Context(), platformUser); err != nil {
			c.JSON(http.StatusInternalServerError, models.PlatformTokenErrorResponse{
				Error:            "server_error",
				ErrorDescription: "unable to link platform account",
			})
			return
		}

		userID = accountID
	}

	// Step 7: Check for user bans
	userStore := store.NewUserStore(db)
	banned, err := userStore.IsUserBannedByAccount(c.Request.Context(), userID, namespace)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.PlatformTokenErrorResponse{
			Error:            "server_error",
			ErrorDescription: "unable to check user ban status",
		})
		return
	}
	if banned {
		c.JSON(http.StatusForbidden, models.PlatformTokenErrorResponse{
			Error:            "access_denied",
			ErrorDescription: "user is banned from login",
			UserBan: &models.Ban{
				Reason: "Account banned",
			},
		})
		return
	}

	// Step 8: Generate access token
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		UserID:       userID,
		Request:      c.Request,
	}

	ti, genErr := s.Manager.GenerateAccessToken(c.Request.Context(), oauth2.PasswordCredentials, tgr)
	if genErr != nil {
		c.JSON(http.StatusInternalServerError, models.PlatformTokenErrorResponse{
			Error:            "server_error",
			ErrorDescription: "token generation failed",
		})
		return
	}

	// Step 9: Build response
	response := models.PlatformTokenResponse{
		AccessToken:    ti.GetAccess(),
		RefreshToken:   ti.GetRefresh(),
		ExpiresIn:      int(ti.GetAccessExpiresIn() / time.Second),
		TokenType:      "Bearer",
		UserID:         userID,
		PlatformID:     platformID,
		PlatformUserID: platformUserInfo.PlatformUserID,
		DisplayName:    platformUserInfo.DisplayName,
		Namespace:      namespace,
		JusticeFlags:   0,
		IsComply:       true,
		Scope:          ti.GetScope(),
	}

	// Add XUID for Xbox platforms
	if platformID == "live" || platformID == "xblweb" {
		response.XUID = platformUserInfo.XUID
	}

	// Set cookies if not skipped
	if !req.SkipSetCookie {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "access_token",
			Value:    ti.GetAccess(),
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(ti.GetAccessExpiresIn() / time.Second),
		})
		if ti.GetRefresh() != "" {
			http.SetCookie(c.Writer, &http.Cookie{
				Name:     "refresh_token",
				Value:    ti.GetRefresh(),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(ti.GetRefreshExpiresIn() / time.Second),
			})
		}
	}

	c.JSON(http.StatusOK, response)
}

// hasWhitespace checks if a string contains any whitespace characters.
func hasWhitespace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// HandleListPlatformClientsGin lists all platform clients for a namespace.
// Route: GET /iam/v1/admin/namespaces/:ns/platform-clients
func (s *Server) HandleListPlatformClientsGin(c *gin.Context) {
	namespace := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	if namespace == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace is required",
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

	platformClientStore := store.NewPlatformClientStore(db)
	clients, err := platformClientStore.GetByNamespace(c.Request.Context(), namespace)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to query platform clients",
		})
		return
	}

	c.JSON(http.StatusOK, clients)
}

// HandleGetPlatformClientGin retrieves a specific platform client.
// Route: GET /iam/v1/admin/namespaces/:ns/platform-clients/:platformId
func (s *Server) HandleGetPlatformClientGin(c *gin.Context) {
	namespace := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	platformID := strings.ToLower(strings.TrimSpace(c.Param("platformId")))

	if namespace == "" || platformID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace and platformId are required",
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

	platformClientStore := store.NewPlatformClientStore(db)
	client, err := platformClientStore.GetByNamespaceAndPlatform(c.Request.Context(), namespace, platformID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to query platform client",
		})
		return
	}

	if client == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "platform client not found",
		})
		return
	}

	c.JSON(http.StatusOK, dto.FromPlatformClient(client))
}

// HandleCreatePlatformClientGin creates a new platform client configuration.
// Route: POST /iam/v1/admin/namespaces/:ns/platform-clients
func (s *Server) HandleCreatePlatformClientGin(c *gin.Context) {
	namespace := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	if namespace == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace is required",
		})
		return
	}

	var req dto.PlatformClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid JSON body: " + err.Error(),
		})
		return
	}

	// Validate required fields
	if req.PlatformID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "platform_id is required",
		})
		return
	}
	if req.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	// Convert to model and set namespace from path
	platformClient := req.ToModel()
	platformClient.Namespace = namespace
	platformClient.PlatformID = strings.ToLower(req.PlatformID)

	db, err := s.GetPrimaryDB()
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

	platformClientStore := store.NewPlatformClientStore(db)

	// Check if already exists
	existing, err := platformClientStore.GetByNamespaceAndPlatform(c.Request.Context(), namespace, platformClient.PlatformID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to check existing platform client",
		})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":             "conflict",
			"error_description": "platform client already exists for this namespace",
		})
		return
	}

	if err := platformClientStore.Create(c.Request.Context(), platformClient); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to create platform client: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, dto.FromPlatformClient(platformClient))
}

// HandleUpdatePlatformClientGin updates an existing platform client configuration.
// Route: PUT /iam/v1/admin/namespaces/:ns/platform-clients/:platformId
func (s *Server) HandleUpdatePlatformClientGin(c *gin.Context) {
	namespace := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	platformID := strings.ToLower(strings.TrimSpace(c.Param("platformId")))

	if namespace == "" || platformID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace and platformId are required",
		})
		return
	}

	var req dto.PlatformClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "invalid JSON body: " + err.Error(),
		})
		return
	}

	db, err := s.GetPrimaryDB()
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

	platformClientStore := store.NewPlatformClientStore(db)

	// Check if exists
	existing, err := platformClientStore.GetByNamespaceAndPlatform(c.Request.Context(), namespace, platformID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to query platform client",
		})
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "platform client not found",
		})
		return
	}

	// Convert to model and preserve ID, namespace, and active status from existing record
	platformClient := req.ToModel()
	platformClient.ID = existing.ID
	platformClient.Namespace = namespace
	platformClient.PlatformID = platformID
	platformClient.CreatedAt = existing.CreatedAt
	platformClient.Active = existing.Active // Preserve active status

	if err := platformClientStore.Update(c.Request.Context(), platformClient); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to update platform client",
		})
		return
	}

	c.JSON(http.StatusOK, dto.FromPlatformClient(platformClient))
}

// HandleDeletePlatformClientGin deletes a platform client configuration.
// Route: DELETE /iam/v1/admin/namespaces/:ns/platform-clients/:platformId
func (s *Server) HandleDeletePlatformClientGin(c *gin.Context) {
	namespace := strings.ToUpper(strings.TrimSpace(c.Param("ns")))
	platformID := strings.ToLower(strings.TrimSpace(c.Param("platformId")))

	if namespace == "" || platformID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "namespace and platformId are required",
		})
		return
	}

	db, err := s.GetPrimaryDB()
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

	platformClientStore := store.NewPlatformClientStore(db)

	// Check if exists
	existing, err := platformClientStore.GetByNamespaceAndPlatform(c.Request.Context(), namespace, platformID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to query platform client",
		})
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "platform client not found",
		})
		return
	}

	if err := platformClientStore.Delete(c.Request.Context(), namespace, platformID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "unable to delete platform client",
		})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}
