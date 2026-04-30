package challenges

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
)

type Dispatcher struct {
	js       *JSHandler
	css      *CSSHandler
	sc       *ScryptHandler
	fp       *FingerprintHandler
	cookie   *CookieChallenge
	tor      *TorExitList
	static   *staticHandler
	strategy string
	basePath string
	log      *slog.Logger
}

func NewDispatcher(
	s *store.Store,
	tm *token.Manager,
	tokenSecret string,
	torFriendly bool,
	torURL string,
	torRefresh time.Duration,
	strategy string,
	basePath string,
	jsDiff, torJSDiff int,
	nonceTTL time.Duration,
	cssSeqLen int,
	scryptDiff, scryptN, scryptR, scryptP, scryptKeyLen int,
	torScryptDiff int,
	log *slog.Logger,
) *Dispatcher {
	var tor *TorExitList
	if torFriendly && torURL != "" {
		tor = NewTorExitList(torURL, torRefresh, log)
	}
	return &Dispatcher{
		js:       NewJSHandler(s, tm, nonceTTL, jsDiff, basePath, log),
		css:      NewCSSHandler(s, tm, nonceTTL, cssSeqLen, basePath, log),
		sc:       NewScryptHandler(s, tm, nonceTTL, scryptDiff, scryptN, scryptR, scryptP, scryptKeyLen, basePath, log),
		fp:       NewFingerprintHandler(s, tm, nonceTTL, basePath, log),
		cookie:   NewCookieChallenge(tokenSecret, tm),
		static:   newStaticHandler(),
		tor:      tor,
		strategy: strategy,
		basePath: strings.TrimRight(basePath, "/"),
		log:      log,
	}
}

func (d *Dispatcher) RegisterRoutes(mux *http.ServeMux) {
	base := d.basePath
	mux.HandleFunc(base+"/js", d.js.ServeHTTP)
	mux.HandleFunc(base+"/verify-js", d.js.ServeHTTP)
	mux.HandleFunc(base+"/css", d.css.ServeHTTP)
	mux.HandleFunc(base+"/css/", d.css.ServeHTTP)
	mux.HandleFunc(base+"/scrypt", d.sc.ServeHTTP)
	mux.HandleFunc(base+"/verify-scrypt", d.sc.ServeHTTP)
	mux.HandleFunc(base+"/fingerprint", d.fp.ServeHTTP)
	mux.HandleFunc(base+"/verify-fingerprint", d.fp.ServeHTTP)
	mux.Handle(base+"/static/", d.static)
}

func (d *Dispatcher) Dispatch(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)
	redirect := r.URL.RequestURI()

	// Fast path: CSS session already validated → promote to WAF token
	if sessID, ok := d.css.IsValidated(r); ok {
		d.css.store.Delete("css:" + sessID)
		http.SetCookie(w, &http.Cookie{Name: "waf_css", Value: "", Path: "/", MaxAge: -1})
		tok := d.css.tokenMgr.Issue(ip)
		secure := r.Header.Get("X-Forwarded-Proto") == "https"
		w.Header().Set("Set-Cookie", token.CookieHeader(tok, d.css.tokenMgr.TTL(), secure))
		d.log.Info("dispatcher: CSS session promoted to token", "ip", ip)
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	kind := d.selectChallenge(ip, r)
	if kind == "cookie" {
		d.cookie.Handle(w, r)
		return
	}
	target := fmt.Sprintf("%s/%s?redirect=%s", d.basePath, kind, urlPercentEncode(redirect))
	http.Redirect(w, r, target, http.StatusFound)
}

func (d *Dispatcher) selectChallenge(ip string, r *http.Request) string {
	isTor := d.tor != nil && d.tor.Contains(ip)

	// session middleware sets this from policy engine match.
	if ch := r.Header.Get("X-WAF-Policy-Challenge"); ch != "" && ch != "none" {
		return ch
	}

	// flagged subnet/fingerprint -> always scrypt.
	if r.Header.Get("X-WAF-Rep-Score") != "" {
		return "scrypt"
	}

	switch d.strategy {
	case "css_first":
		return "css"
	case "scrypt_for_datacenter":
		if isDatacenterIP(ip) {
			return "scrypt"
		}
		if isTor {
			return "js"
		}
		return "js"
	default: // js_first
		if isTor {
			return "js"
		}
		return "js"
	}
}

// isDatacenterIP is a thin shim so the rest of the dispatcher package continues to call the same name after we moved the logic to datacenter.go.
func isDatacenterIP(ip string) bool {
	return IsDatacenterIP(ip)
}
