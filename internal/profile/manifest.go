package profile

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	profileIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	semverRE    = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([-+][0-9A-Za-z.-]+)?$`)
)

func DecodeManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("decode manifest: %w", err)
	}
	if err := ValidateManifest(m); err != nil {
		return m, err
	}
	return m, nil
}

func ValidateManifest(m Manifest) error {
	if m.APIVersion != APIVersion {
		return fmt.Errorf("unsupported apiVersion %q", m.APIVersion)
	}
	if m.Kind != Kind {
		return fmt.Errorf("kind must be %q", Kind)
	}
	if !profileIDRE.MatchString(m.Metadata.ID) {
		return errors.New("metadata.id must be 2-63 lowercase letters, numbers or hyphens")
	}
	if strings.TrimSpace(m.Metadata.Name) == "" || len(m.Metadata.Name) > 120 {
		return errors.New("metadata.name is required and must be at most 120 characters")
	}
	if !semverRE.MatchString(m.Metadata.Version) {
		return errors.New("metadata.version must be semantic version (x.y.z)")
	}
	for label, p := range map[string]string{
		"spec.rules.path":        m.Spec.Rules.Path,
		"spec.integrations.path": m.Spec.Integrations.Path,
		"spec.config.path":       m.Spec.Config.Path,
	} {
		if p == "" {
			continue
		}
		p = strings.TrimSuffix(p, "/")
		if p == "" || path.IsAbs(p) || path.Clean(p) != p || strings.HasPrefix(p, "../") || strings.Contains(p, `\`) {
			return fmt.Errorf("%s is not a safe relative directory", label)
		}
	}
	if m.Spec.Rules.Enabled && m.Spec.Rules.Path == "" {
		return errors.New("rules.path is required when rules are enabled")
	}
	if m.Spec.Integrations.Enabled && m.Spec.Integrations.Path == "" {
		return errors.New("integrations.path is required when integrations are enabled")
	}
	return nil
}
