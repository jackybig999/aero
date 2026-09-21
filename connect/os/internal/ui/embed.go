package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// GetHTMLUI returns the bundled HTML page with inlined CSS and JS for w.SetHtml()
func GetHTMLUI() string {
	indexHTML, err := distFS.ReadFile("dist/index.html")
	if err != nil {
		return "<html><body><h3>Failed to load UI assets</h3></body></html>"
	}
	styleCSS, _ := distFS.ReadFile("dist/style.css")
	bridgeJS, _ := distFS.ReadFile("dist/bridge.js")
	appJS, _ := distFS.ReadFile("dist/app.js")

	html := string(indexHTML)

	// Replace external stylesheet with inlined style
	cssTag := fmt.Sprintf("<style>\n%s\n</style>", string(styleCSS))
	html = strings.Replace(html, `<link rel="stylesheet" href="style.css" />`, cssTag, 1)

	// Replace external scripts with inlined scripts
	bridgeTag := fmt.Sprintf("<script>\n%s\n</script>", string(bridgeJS))
	html = strings.Replace(html, `<script src="bridge.js"></script>`, bridgeTag, 1)

	appTag := fmt.Sprintf("<script>\n%s\n</script>", string(appJS))
	html = strings.Replace(html, `<script src="app.js"></script>`, appTag, 1)

	return html
}

// GetFS returns the filesystem of embedded UI dist assets
func GetFS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
