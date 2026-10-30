package profile

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

const (
	MaxArchiveBytes  = 20 << 20
	MaxExpandedBytes = 50 << 20
	MaxEntries       = 256
	MaxEntryBytes    = 4 << 20
)

type Bundle struct {
	Manifest Manifest
	Files    map[string][]byte
}

func ReadArchive(data []byte) (*Bundle, error) {
	if len(data) == 0 || len(data) > MaxArchiveBytes {
		return nil, fmt.Errorf("ZIP size must be between 1 byte and %d bytes", MaxArchiveBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open profile ZIP: %w", err)
	}
	if len(zr.File) == 0 || len(zr.File) > MaxEntries {
		return nil, fmt.Errorf("archive must contain 1..%d entries", MaxEntries)
	}

	files := make(map[string][]byte, len(zr.File))
	var expanded int64
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, `\`, "/")
		isDir := strings.HasSuffix(name, "/")
		if isDir {
			name = strings.TrimSuffix(name, "/")
		}
		if !utf8.ValidString(name) || name == "" || strings.HasPrefix(name, "/") ||
			path.Clean(name) != name || name == "." || strings.Contains(name, ":") {
			return nil, fmt.Errorf("unsafe ZIP path %q", f.Name)
		}
		for _, part := range strings.Split(name, "/") {
			if part == "" || part == "." || part == ".." {
				return nil, fmt.Errorf("unsafe ZIP path %q", f.Name)
			}
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symbolic links are not allowed: %s", name)
		}
		if isDir || f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 > MaxEntryBytes {
			return nil, fmt.Errorf("entry %s exceeds %d bytes", name, MaxEntryBytes)
		}
		expanded += int64(f.UncompressedSize64)
		if expanded > MaxExpandedBytes {
			return nil, fmt.Errorf("expanded archive exceeds %d bytes", MaxExpandedBytes)
		}
		if _, exists := files[name]; exists {
			return nil, fmt.Errorf("duplicate ZIP entry %q", name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", name, err)
		}
		b, readErr := io.ReadAll(io.LimitReader(rc, MaxEntryBytes+1))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(b) > MaxEntryBytes {
			return nil, fmt.Errorf("entry %s is too large", name)
		}
		files[name] = b
	}
	manifestBytes, ok := files["manifest.yaml"]
	if !ok {
		manifestBytes, ok = files["manifest.yml"]
	}
	if !ok {
		return nil, errors.New("manifest.yaml is required at ZIP root")
	}
	m, err := DecodeManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	return &Bundle{Manifest: m, Files: files}, nil
}
