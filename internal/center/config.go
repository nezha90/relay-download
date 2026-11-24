package center

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen         string `yaml:"listen"`
	TLSCert        string `yaml:"tls_cert"`
	TLSKey         string `yaml:"tls_key"`
	CACert         string `yaml:"ca_cert"`
	DBPath         string `yaml:"db_path"`
	JWTSecret      string `yaml:"jwt_secret"`
	CenterSecret   string `yaml:"center_secret"`
	AdminToken     string `yaml:"admin_token"`
	NodeOfflineSec int    `yaml:"node_offline_sec"`
	JWTTTLSec      int    `yaml:"jwt_ttl_sec"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse center config: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8440"
	}
	if c.DBPath == "" {
		c.DBPath = "./data-center/center.db"
	}
	if c.NodeOfflineSec <= 0 {
		c.NodeOfflineSec = 20
	}
	if c.JWTTTLSec <= 0 {
		c.JWTTTLSec = 900 // 15 minutes
	}
}

func (c *Config) Validate() error {
	if c.TLSCert == "" || c.TLSKey == "" {
		return errors.New("tls_cert and tls_key are required")
	}
	if c.JWTSecret == "" {
		return errors.New("jwt_secret is required")
	}
	if c.AdminToken == "" {
		return errors.New("admin_token is required")
	}
	return nil
}

func (c *Config) NodeOfflineTimeout() time.Duration {
	return time.Duration(c.NodeOfflineSec) * time.Second
}

func (c *Config) JWTTTL() time.Duration {
	return time.Duration(c.JWTTTLSec) * time.Second
}
