package profile

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

type fakeRules struct{ ids map[string]bool }

func (f *fakeRules) Validate(b []byte, ext string) (string, error) {
	var v struct {
		ID string `yaml:"id" json:"id"`
	}
	if err := yamlUnmarshal(b, &v); err != nil {
		return "", err
	}
	if v.ID == "" {
		return "", fmt.Errorf("missing id")
	}
	return v.ID, nil
}
func (f *fakeRules) Save(b []byte, ext string) error {
	id, e := f.Validate(b, ext)
	if e == nil {
		f.ids[id] = true
	}
	return e
}
func (f *fakeRules) Delete(id string) error { delete(f.ids, id); return nil }

type fakeIntegrations struct{ values map[string][2]bool }

func (f *fakeIntegrations) Get(id string) (bool, bool, bool) {
	v, ok := f.values[id]
	return v[0], v[1], ok
}
func (f *fakeIntegrations) Update(id string, e, a bool) error {
	if _, ok := f.values[id]; !ok {
		return fmt.Errorf("unknown")
	}
	f.values[id] = [2]bool{e, a}
	return nil
}
func (f *fakeIntegrations) Apply(string) error { return nil }

func yamlUnmarshal(b []byte, v any) error { return yaml.Unmarshal(b, v) }

func makeZIP(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for n, s := range files {
		f, e := w.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte(s)); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestInstallAndDeleteProfile(t *testing.T) {
	r := &fakeRules{ids: map[string]bool{}}
	i := &fakeIntegrations{values: map[string][2]bool{"syslog-files": {false, true}}}
	m, e := NewManager(t.TempDir(), r, i)
	if e != nil {
		t.Fatal(e)
	}
	z := makeZIP(t, map[string]string{
		"manifest.yaml":            "apiVersion: rasadbin.io/v1\nkind: SecurityProfile\nmetadata:\n  id: linux-base\n  name: Linux Base\n  version: 1.0.0\nspec:\n  rules: {enabled: true, path: rules}\n  integrations: {enabled: true, path: integrations, auto_enable: true}\n  config: {path: config}\n",
		"rules/auth.yaml":          "id: ssh_auth\n",
		"integrations/syslog.yaml": "id: syslog-files\nenabled: true\nalerting: true\n",
		"config/detection.yaml":    "threshold: 8\n",
	})
	if _, e = m.Validate(z); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Install(z); e != nil {
		t.Fatal(e)
	}
	if !r.ids["ssh_auth"] || !i.values["syslog-files"][0] {
		t.Fatal("profile resources not installed")
	}
	if e = m.Delete("linux-base"); e != nil {
		t.Fatal(e)
	}
	if r.ids["ssh_auth"] || i.values["syslog-files"][0] {
		t.Fatal("owned resources not reverted")
	}
}
func TestRejectZipSlip(t *testing.T) {
	z := makeZIP(t, map[string]string{"../escape": "bad", "manifest.yaml": "apiVersion: rasadbin.io/v1"})
	r := &fakeRules{ids: map[string]bool{}}
	i := &fakeIntegrations{values: map[string][2]bool{}}
	m, _ := NewManager(t.TempDir(), r, i)
	if _, e := m.Validate(z); e == nil {
		t.Fatal("expected traversal rejection")
	}
}
