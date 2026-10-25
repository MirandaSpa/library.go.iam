// Package manifestfile reads the permissions.yaml a service keeps in its repo. It
// is apart from the iam package because it needs a YAML library, and iam itself
// uses only the standard library.
package manifestfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"

	iam "github.com/MirandaSpa/library.go.iam"
)

// Load reads and validates the manifest at path.
func Load(path string) (iam.Manifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is the service's own permissions.yaml, from its code or configuration
	if err != nil {
		return iam.Manifest{}, fmt.Errorf("iam: read manifest: %w", err)
	}
	return Parse(data)
}

// Parse decodes and validates a manifest. An unknown key is an error, so a typo
// in the file does not silently drop a permission.
func Parse(data []byte) (iam.Manifest, error) {
	var m iam.Manifest
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		if errors.Is(err, io.EOF) {
			return iam.Manifest{}, errors.New("iam: the manifest is empty")
		}
		return iam.Manifest{}, fmt.Errorf("iam: decode manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return iam.Manifest{}, err
	}
	return m, nil
}
