package manifestfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MirandaSpa/library.go.iam/manifestfile"
)

const valid = `service: products
permissions:
  - id: products:product:list
    label: Ver catalogo
    description: Permite ver el catalogo.
    scope: global
routes:
  - method: GET
    path: /api/v2/internal_product/products
    permission: products:product:list
  - method: GET
    path: /api/v2/internal_product/products/test
    public: true
`

func TestParse(t *testing.T) {
	t.Run("reads a valid manifest", func(t *testing.T) {
		m, err := manifestfile.Parse([]byte(valid))
		require.NoError(t, err)
		assert.Equal(t, "products", m.Service)
		require.Len(t, m.Permissions, 1)
		assert.Equal(t, "global", m.Permissions[0].Scope)
		require.Len(t, m.Routes, 2)
		assert.True(t, m.Routes[1].Public)
	})

	t.Run("an unknown key is an error, so a typo does not drop a field", func(t *testing.T) {
		_, err := manifestfile.Parse([]byte(valid + "  extra: 1\n"))
		require.Error(t, err)
		_, err = manifestfile.Parse([]byte("service: products\npermission_list: []\n"))
		require.ErrorContains(t, err, "permission_list")
	})

	t.Run("an empty file is an error", func(t *testing.T) {
		_, err := manifestfile.Parse(nil)
		require.ErrorContains(t, err, "empty")
	})

	t.Run("broken yaml is an error", func(t *testing.T) {
		_, err := manifestfile.Parse([]byte("service: [unclosed"))
		require.Error(t, err)
	})

	t.Run("a manifest that does not validate is an error", func(t *testing.T) {
		_, err := manifestfile.Parse([]byte("service: products\npermissions:\n  - id: other:a:b\n    label: X\n"))
		require.ErrorContains(t, err, "must start with the service")
	})
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissions.yaml")
	require.NoError(t, os.WriteFile(path, []byte(valid), 0o600))

	m, err := manifestfile.Load(path)
	require.NoError(t, err)
	assert.Equal(t, "products", m.Service)

	_, err = manifestfile.Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
}
