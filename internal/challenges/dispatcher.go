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
	tor      *TorExitList
	strategy string
	basePath string
	log      *slog.Logger
}

func NewDispatcher(
	s *store.Store,
	tm *token.Manager,
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

	kind := d.selectChallenge(ip)
	target := fmt.Sprintf("%s/%s?redirect=%s", d.basePath, kind, urlPercentEncode(redirect))
	http.Redirect(w, r, target, http.StatusFound)
}

func (d *Dispatcher) selectChallenge(ip string) string {
	isTor := d.tor != nil && d.tor.Contains(ip)
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

func isDatacenterIP(ip string) bool {
	for _, p := range []string{
		"3.", "13.", "15.", "18.", "34.", "35.", "52.", "54.",
		"20.", "40.", "51.", "104.45.", "137.", "138.",
		"130.", "142.", "146.",
		"104.16.", "104.17.", "104.18.", "104.19.",
		"45.33.", "96.126.", "173.255.",
	} {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}
