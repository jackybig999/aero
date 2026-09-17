package public

import (
	"embed"
	"io/fs"
)

//go:embed all:renderer
var rendererFS embed.FS

// GetRendererFS returns the embedded web UI filesystem.
func GetRendererFS() (fs.FS, error) {
	return fs.Sub(rendererFS, "renderer")
}
