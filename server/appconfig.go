package server

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// AppConfig defines application configuration loaded from files and environment.
type AppConfig struct {
	Env      string         `koanf:"env"`
	Database DatabaseConfig `koanf:"database"`
}

type DatabaseConfig struct {
	User DSNConfig `koanf:"user"`
	Reg  DSNConfig `koanf:"reg"`
}

type DSNConfig struct {
	DSN string `koanf:"dsn"`
}

var (
	cfgOnce sync.Once
	cfgInst *AppConfig
)

// GetConfig loads and returns the singleton AppConfig. Loading order:
// 1) config/config.yaml (optional)
// 2) config/config.<APP_ENV>.yaml (optional), APP_ENV defaults to "local"
// 3) Environment variables with prefix IAM_ mapped using __ as nested separator, e.g. IAM_DATABASE__USER__DSN
func GetConfig() *AppConfig {
	cfgOnce.Do(func() {
		k := koanf.New(".")
		// Config directory (CONFIG_DIR) default ./config
		configDir := os.Getenv("CONFIG_DIR")
		if configDir == "" {
			configDir = "config"
		}
		// Whether to load files (default: disabled to keep tests isolated)
		loadFiles := strings.EqualFold(os.Getenv("APP_CONFIG_FILES"), "1") || strings.EqualFold(os.Getenv("APP_CONFIG_FILES"), "true")
		// 1) base file
		if loadFiles {
			base := filepath.Join(configDir, "config.yaml")
			if _, err := os.Stat(base); err == nil {
				if err := k.Load(file.Provider(base), yaml.Parser()); err != nil {
					log.Printf("config: failed loading base: %v", err)
				}
			}
		}
		// 2) env-specific file
		envName := os.Getenv("APP_ENV")
		if envName == "" {
			envName = "local"
		}
		if loadFiles {
			envFile := filepath.Join(configDir, "config."+envName+".yaml")
			if _, err := os.Stat(envFile); err == nil {
				if err := k.Load(file.Provider(envFile), yaml.Parser()); err != nil {
					log.Printf("config: failed loading env file: %v", err)
				}
			}
		}
		// 3) env vars: IAM_ prefix, __ delim for nesting
		_ = k.Load(env.Provider("IAM_", "__", func(s string) string {
			// IAM_DATABASE__USER__DSN -> database.user.dsn
			return s
		}), nil)

		var c AppConfig
		if err := k.Unmarshal("", &c); err != nil {
			log.Printf("config: unmarshal error: %v", err)
		}
		if c.Env == "" {
			c.Env = envName
		}
		cfgInst = &c
	})
	return cfgInst
}

// RegDBDSN returns the effective DSN for client registration DB (config first, then env).
func (c *AppConfig) RegDBDSN() string {
	if c != nil && c.Database.Reg.DSN != "" {
		return strings.TrimSpace(c.Database.Reg.DSN)
	}
	return strings.TrimSpace(os.Getenv("REG_DB_DSN"))
}

// UserDBDSN returns the effective DSN for accounts DB (config first, then env fallback to MIGRATE_DSN).
func (c *AppConfig) UserDBDSN() string {
	if c != nil && c.Database.User.DSN != "" {
		return strings.TrimSpace(c.Database.User.DSN)
	}
	dsn := strings.TrimSpace(os.Getenv("USER_DB_DSN"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("MIGRATE_DSN"))
	}
	return dsn
}
