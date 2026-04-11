package challenges

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed templates
var embeddedTemplates embed.FS

// templates holds the parsed challenge page templates.
// They are initialised once at startup by LoadTemplates.
var (
	tmplJS          *template.Template
	tmplScrypt      *template.Template
	tmplCSS         *template.Template
	tmplFingerprint *template.Template
)

// LoadTemplates parses all challenge page templates.
//
// If templateDir is non-empty the templates in that directory take precedence
// over the embedded defaults — any file present on disk overrides its
// embedded counterpart, missing files fall back to the embed.  This lets
// operators customise branding without a recompile.
//
// Template file names (relative to templateDir or the embedded "templates/"
// directory):
//
//	js_pow.html        — JS proof-of-work challenge
//	scrypt.html        — memory-hard scrypt challenge
//	css.html           — no-JS CSS challenge
//	fingerprint.html   — browser fingerprint challenge
func LoadTemplates(templateDir string) error {
	type entry struct {
		name string
		dest **template.Template
	}
	entries := []entry{
		{"js_pow.html", &tmplJS},
		{"scrypt.html", &tmplScrypt},
		{"css.html", &tmplCSS},
		{"fingerprint.html", &tmplFingerprint},
	}

	for _, e := range entries {
		src, err := loadTemplateSource(templateDir, e.name)
		if err != nil {
			return fmt.Errorf("challenges: loading template %q: %w", e.name, err)
		}
		t, err := template.New(e.name).Parse(src)
		if err != nil {
			return fmt.Errorf("challenges: parsing template %q: %w", e.name, err)
		}
		*e.dest = t
	}
	return nil
}

// loadTemplateSource returns the raw template source for name.
// If templateDir is set and the file exists there, the disk version wins.
// Otherwise the embedded version is returned.
func loadTemplateSource(templateDir, name string) (string, error) {
	if templateDir != "" {
		diskPath := filepath.Join(templateDir, name)
		if data, err := os.ReadFile(diskPath); err == nil {
			return string(data), nil
		}
		// File absent on disk — fall through to embedded.
	}

	embeddedPath := filepath.Join("templates", name)
	data, err := fs.ReadFile(embeddedTemplates, embeddedPath)
	if err != nil {
		return "", fmt.Errorf("embedded template %q not found: %w", embeddedPath, err)
	}
	return string(data), nil
}

// mustTemplate panics if t is nil (i.e. LoadTemplates was not called).
// Used by handlers to provide a clear error instead of a nil-pointer crash.
func mustTemplate(name string, t *template.Template) *template.Template {
	if t == nil {
		panic("challenges: template " + name + " not loaded — call LoadTemplates first")
	}
	return t
}
