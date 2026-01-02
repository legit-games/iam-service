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
	Migrate  MigrateConfig  `koanf:"migrate"`
}

type DatabaseConfig struct {
	IAM DSNGroup `koanf:"iam"`
}

type DSNGroup struct {
	DSN   string   `koanf:"dsn"`
	Read  DSNEntry `koanf:"read"`
	Write DSNEntry `koanf:"write"`
}

type DSNEntry struct {
	DSN string `koanf:"dsn"`
}

type MigrateConfig struct {
	OnStart bool   `koanf:"on_start"`
	Driver  string `koanf:"driver"`
	DSN     string `koanf:"dsn"`
	Cmd     string `koanf:"cmd"`
	Target  int64  `koanf:"target"`
}

var (
	cfgOnce sync.Once
	cfgInst *AppConfig
)

// GetConfig loads and returns the singleton AppConfig. Loading order:
// 1) config/config.yaml (optional)
// 2) config/config.<APP_ENV>.yaml (optional), APP_ENV defaults to "local"
// 3) Environment variables with prefix IAM_ mapped using __ as nested separator
func GetConfig() *AppConfig {
	cfgOnce.Do(func() {
		k := koanf.New(".")
		configDir := resolveConfigDir()
		log.Printf("config: using directory: %s", configDir)
		// Always try base config
		base := filepath.Join(configDir, "config.yaml")
		if _, err := os.Stat(base); err == nil {
			if err := k.Load(file.Provider(base), yaml.Parser()); err != nil {
				log.Printf("config: failed loading base file: %s: %v", base, err)
			} else {
				log.Printf("config: loaded base file: %s", base)
			}
		} else {
			log.Printf("config: base file not found: %s", base)
		}
		// Env-specific
		envName := os.Getenv("APP_ENV")
		if envName == "" {
			envName = "local"
		}
		log.Printf("config: APP_ENV=%s", envName)
		envFile := filepath.Join(configDir, "config."+envName+".yaml")
		if _, err := os.Stat(envFile); err == nil {
			if err := k.Load(file.Provider(envFile), yaml.Parser()); err != nil {
				log.Printf("config: failed loading env file: %s: %v", envFile, err)
			} else {
				log.Printf("config: loaded env file: %s", envFile)
			}
		} else {
			log.Printf("config: env file not found: %s", envFile)
		}
		// Also load test overrides if present
		testFile := filepath.Join(configDir, "config.test.yaml")
		if _, err := os.Stat(testFile); err == nil {
			if err := k.Load(file.Provider(testFile), yaml.Parser()); err != nil {
				log.Printf("config: failed loading test override: %s: %v", testFile, err)
			} else {
				log.Printf("config: loaded test override: %s", testFile)
			}
		} else {
			log.Printf("config: test override not found: %s", testFile)
		}
		// Env vars
		if err := k.Load(env.Provider("IAM_", "__", func(s string) string { return s }), nil); err != nil {
			log.Printf("config: failed loading IAM_ environment variables: %v", err)
		} else {
			log.Printf("config: loaded IAM_ environment variables")
		}

		var c AppConfig
		// Unmarshal
		if err := k.Unmarshal("", &c); err != nil {
			log.Printf("config: unmarshal error: %v", err)
		}
		if c.Env == "" {
			c.Env = envName
		}
		log.Printf("config: effective env=%s", c.Env)
		cfgInst = &c
	})
	return cfgInst
}

// resolveConfigDir returns the best-effort config directory path.
// Priority: CONFIG_DIR env → ./config → ../config relative to working dir → module root/config
func resolveConfigDir() string {
	if v := strings.TrimSpace(os.Getenv("CONFIG_DIR")); v != "" {
		return v
	}
	cwd, _ := os.Getwd()
	cand := filepath.Join(cwd, "config")
	if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
		return cand
	}
	cand2 := filepath.Join(filepath.Dir(cwd), "config")
	if fi, err := os.Stat(cand2); err == nil && fi.IsDir() {
		return cand2
	}
	// Walk up to find go.mod as module root and use its config
	root := findModuleRoot(cwd)
	if root != "" {
		cand3 := filepath.Join(root, "config")
		if fi, err := os.Stat(cand3); err == nil && fi.IsDir() {
			return cand3
		}
	}
	// Fallback to relative 'config'
	return "config"
}

// findModuleRoot walks up directories from start to locate go.mod.
func findModuleRoot(start string) string {
	cur := start
	for i := 0; i < 5; i++ { // limit depth to avoid infinite loops
		gomod := filepath.Join(cur, "go.mod")
		if _, err := os.Stat(gomod); err == nil {
			return cur
		}
		next := filepath.Dir(cur)
		if next == cur {
			break
		}
		cur = next
	}
	return ""
}

// UserReadDSN returns the effective read DSN for accounts DB.
func (c *AppConfig) UserReadDSN() string {
	if c != nil {
		if c.Database.IAM.Read.DSN != "" {
			return strings.TrimSpace(c.Database.IAM.Read.DSN)
		}
		if c.Database.IAM.DSN != "" {
			return strings.TrimSpace(c.Database.IAM.DSN)
		}
	}
	if v := strings.TrimSpace(os.Getenv("IAM_DB_READ_DSN")); v != "" {
		return v
	}
	v := strings.TrimSpace(os.Getenv("IAM_DB_DSN"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("MIGRATE_DSN"))
	}
	return v
}

// UserWriteDSN returns the effective write DSN for accounts DB.
func (c *AppConfig) UserWriteDSN() string {
	if c != nil {
		if c.Database.IAM.Write.DSN != "" {
			return strings.TrimSpace(c.Database.IAM.Write.DSN)
		}
		if c.Database.IAM.DSN != "" {
			return strings.TrimSpace(c.Database.IAM.DSN)
		}
	}
	if v := strings.TrimSpace(os.Getenv("IAM_DB_WRITE_DSN")); v != "" {
		return v
	}
	v := strings.TrimSpace(os.Getenv("IAM_DB_DSN"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("MIGRATE_DSN"))
	}
	return v
}

// MigrateOptionsFromConfig returns values suitable for migrate.Options and whether migration is enabled.
func (c *AppConfig) MigrateOptionsFromConfig() (enabled bool, driver string, dsn string, cmd string, target int64) {
	if c == nil {
		return false, "", "", "", 0
	}
	enabled = c.Migrate.OnStart
	driver = strings.TrimSpace(c.Migrate.Driver)
	dsn = strings.TrimSpace(c.Migrate.DSN)
	cmd = strings.TrimSpace(c.Migrate.Cmd)
	if cmd == "" {
		cmd = "up"
	}
	target = c.Migrate.Target
	// Infer driver from DSN if missing
	if driver == "" {
		if strings.HasPrefix(dsn, "postgres://") {
			driver = "postgres"
		}
		if strings.HasPrefix(dsn, "sqlite:") || strings.HasSuffix(dsn, ".db") {
			driver = "sqlite"
		}
	}
	return
}
