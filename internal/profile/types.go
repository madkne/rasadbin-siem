package profile

import "time"

const (
	APIVersion = "rasadbin.io/v1"
	Kind       = "SecurityProfile"
)

type Manifest struct {
	APIVersion string      `yaml:"apiVersion" json:"apiVersion"`
	Kind       string      `yaml:"kind" json:"kind"`
	Metadata   Metadata    `yaml:"metadata" json:"metadata"`
	Spec       ProfileSpec `yaml:"spec" json:"spec"`
}

type Metadata struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Version     string   `yaml:"version" json:"version"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Author      string   `yaml:"author,omitempty" json:"author,omitempty"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

type ProfileSpec struct {
	Rules        ResourceSpec    `yaml:"rules" json:"rules"`
	Integrations IntegrationSpec `yaml:"integrations" json:"integrations"`
	Config       ConfigSpec      `yaml:"config" json:"config"`
	Requirements Requirements    `yaml:"requirements,omitempty" json:"requirements,omitempty"`
	Defaults     map[string]bool `yaml:"defaults,omitempty" json:"defaults,omitempty"`
}

type ResourceSpec struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path" json:"path"`
}

type IntegrationSpec struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Path       string `yaml:"path" json:"path"`
	AutoEnable bool   `yaml:"auto_enable" json:"auto_enable"`
}

type ConfigSpec struct {
	Path string `yaml:"path" json:"path"`
}

type Requirements struct {
	Platform []string `yaml:"platform,omitempty" json:"platform,omitempty"`
}

type IntegrationConfig struct {
	ID       string `yaml:"id" json:"id"`
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Alerting *bool  `yaml:"alerting,omitempty" json:"alerting,omitempty"`
}

type InstalledProfile struct {
	Manifest     Manifest              `json:"manifest"`
	InstalledAt  time.Time             `json:"installed_at"`
	RuleIDs      []string              `json:"rule_ids,omitempty"`
	Integrations []IntegrationConfig   `json:"integrations,omitempty"`
	Previous     []PreviousIntegration `json:"previous_integrations,omitempty"`
	ConfigFiles  []string              `json:"config_files,omitempty"`
}

type PreviousIntegration struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	Alerting bool   `json:"alerting"`
}

type Preview struct {
	Manifest     Manifest            `json:"manifest"`
	Rules        []string            `json:"rules"`
	Integrations []IntegrationConfig `json:"integrations"`
	ConfigFiles  []string            `json:"config_files"`
	Warnings     []string            `json:"warnings,omitempty"`
}
