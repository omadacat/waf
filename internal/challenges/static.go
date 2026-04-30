package challenges

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var embeddedStatic embed.FS

// staticHandler serves files from the embedded static/ directory.
// Registered at /_waf/static/ by the Dispatcher.
type staticHandler struct {
	fs http.FileSystem
}

func newStaticHandler() *staticHandler {
	sub, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		panic("challenges: embedded static dir missing: " + err.Error())
	}
	return &staticHandler{fs: http.FS(sub)}
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip the /_waf/static prefix so the file server sees /img/neofox_think.png
	// when the request path is /_waf/static/img/neofox_think.png.
	// The prefix varies with basePath so we strip up to and including "/static".
	path := r.URL.Path
	if i := strings.Index(path, "/static"); i >= 0 {
		r = r.Clone(r.Context())
		r.URL.Path = path[i+len("/static"):]
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
	}

	// Cache static assets aggressively — they're embedded in the binary
	// and won't change until the WAF is rebuilt.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.FileServer(h.fs).ServeHTTP(w, r)
}
