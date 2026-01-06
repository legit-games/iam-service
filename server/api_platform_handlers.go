package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/platforms"
	"github.com/go-oauth2/oauth2/v4/store"
)

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
