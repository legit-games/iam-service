package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

type RoleStore struct{ DB *gorm.DB }

func NewRoleStore(db *gorm.DB) *RoleStore { return &RoleStore{DB: db} }

func (s *RoleStore) UpsertRole(ctx context.Context, role models.Role) error {
	role.Namespace = strings.ToUpper(strings.TrimSpace(role.Namespace))
	if role.Namespace == "" || strings.TrimSpace(role.Name) == "" {
		return gorm.ErrInvalidData
	}
	if role.RoleType != models.RoleTypeUser && role.RoleType != models.RoleTypeClient {
		return gorm.ErrInvalidData
	}
	// Upsert by (namespace,name,role_type)
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing models.Role
		err := tx.Where("namespace = ? AND name = ? AND role_type = ?", role.Namespace, role.Name, role.RoleType).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			role.ID = models.LegitID()
			role.CreatedAt = time.Now().UTC()
			return tx.Create(&role).Error
		} else if err != nil {
			return err
		}
		updates := map[string]interface{}{
			"permissions": role.Permissions,
			"description": role.Description,
		}
		return tx.Model(&models.Role{}).Where("id = ?", existing.ID).Updates(updates).Error
	})
}

func (s *RoleStore) ListRoles(ctx context.Context, ns string, roleType *string) ([]models.Role, error) {
	ns = strings.ToUpper(strings.TrimSpace(ns))
	q := s.DB.WithContext(ctx).Model(&models.Role{}).Where("namespace = ?", ns)
	if roleType != nil && *roleType != "" {
		q = q.Where("role_type = ?", *roleType)
	}
	var roles []models.Role
	return roles, q.Order("name ASC").Find(&roles).Error
}

func (s *RoleStore) DeleteRole(ctx context.Context, id string) error {
	return s.DB.WithContext(ctx).Where("id = ?", id).Delete(&models.Role{}).Error
}

func (s *RoleStore) AssignRoleToUser(ctx context.Context, userID, ns, roleID string) error {
	ns = strings.ToUpper(strings.TrimSpace(ns))
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Validate role exists and namespace matches
		var role models.Role
		if err := tx.Where("id = ? AND namespace = ?", roleID, ns).First(&role).Error; err != nil {
			return err
		}
		ur := models.UserRole{ID: models.LegitID(), UserID: userID, RoleID: roleID, Namespace: ns, AssignedAt: time.Now().UTC()}
		return tx.Create(&ur).Error
	})
}

func (s *RoleStore) AssignRoleToClient(ctx context.Context, clientID, ns, roleID string) error {
	ns = strings.ToUpper(strings.TrimSpace(ns))
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var role models.Role
		if err := tx.Where("id = ? AND namespace = ?", roleID, ns).First(&role).Error; err != nil {
			return err
		}
		cr := models.ClientRole{ID: models.LegitID(), ClientID: clientID, RoleID: roleID, Namespace: ns, AssignedAt: time.Now().UTC()}
		return tx.Create(&cr).Error
	})
}

func (s *RoleStore) ListRoleAssignmentsForUser(ctx context.Context, userID, ns string) ([]models.Role, error) {
	ns = strings.ToUpper(strings.TrimSpace(ns))
	var roles []models.Role
	err := s.DB.WithContext(ctx).Table("roles r").Select("r.*").Joins("JOIN user_roles ur ON ur.role_id = r.id").Where("ur.user_id = ? AND ur.namespace = ?", userID, ns).Order("r.name ASC").Scan(&roles).Error
	return roles, err
}

func (s *RoleStore) ListRoleAssignmentsForClient(ctx context.Context, clientID, ns string) ([]models.Role, error) {
	ns = strings.ToUpper(strings.TrimSpace(ns))
	var roles []models.Role
	err := s.DB.WithContext(ctx).Table("roles r").Select("r.*").Joins("JOIN client_roles cr ON cr.role_id = r.id").Where("cr.client_id = ? AND cr.namespace = ?", clientID, ns).Order("r.name ASC").Scan(&roles).Error
	return roles, err
}

func (s *RoleStore) AssignRoleToAllUsersInNamespace(ctx context.Context, ns, roleID string) error {
	ns = strings.ToUpper(strings.TrimSpace(ns))
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Validate role exists in namespace
		var count int64
		if err := tx.Table("roles").Where("id = ? AND namespace = ?", roleID, ns).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return gorm.ErrRecordNotFound
		}
		// Iterate all user ids in namespace and insert mapping if not exists
		rows, err := tx.Raw(`SELECT id FROM users WHERE namespace = ?`, ns).Rows()
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var uid string
			if err := rows.Scan(&uid); err != nil {
				return err
			}
			// Use ON CONFLICT to avoid duplicate
			if err := tx.Exec(`INSERT INTO user_roles (id, user_id, role_id, namespace, assigned_at) VALUES (?,?,?,?,?) ON CONFLICT (user_id, role_id) DO NOTHING`, models.LegitID(), uid, roleID, ns, time.Now().UTC()).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *RoleStore) ListUsersByRole(ctx context.Context, ns, roleID string) ([]string, error) {
	ns = strings.ToUpper(strings.TrimSpace(ns))
	var ids []string
	err := s.DB.WithContext(ctx).Table("user_roles").Select("user_id").Where("namespace = ? AND role_id = ?", ns, roleID).Scan(&ids).Error
	return ids, err
}

func (s *RoleStore) ListClientsByRole(ctx context.Context, ns, roleID string) ([]string, error) {
	ns = strings.ToUpper(strings.TrimSpace(ns))
	var ids []string
	err := s.DB.WithContext(ctx).Table("client_roles").Select("client_id").Where("namespace = ? AND role_id = ?", ns, roleID).Scan(&ids).Error
	return ids, err
}
