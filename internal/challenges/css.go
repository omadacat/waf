package challenges

import (
	"fmt"
	"html/template"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
)

type CSSSession struct {
	IP        string
	Expected  []string
	Loaded    []string
	Validated bool
	Failed    bool
}

type CSSHandler struct {
	store    *store.Store
	tokenMgr *token.Manager
	nonceTTL time.Duration
	seqLen   int
	basePath string
	log      *slog.Logger
}

func NewCSSHandler(s *store.Store, tm *token.Manager, nonceTTL time.Duration, seqLen int, basePath string, log *slog.Logger) *CSSHandler {
	if seqLen < 2 || seqLen > 6 {
		seqLen = 3
	}
	return &CSSHandler{
		store:    s,
		tokenMgr: tm,
		nonceTTL: nonceTTL,
		seqLen:   seqLen,
		basePath: strings.TrimRight(basePath, "/"),
		log:      log,
	}
}

var sequenceLetters = []string{"A", "B", "C", "D", "E", "F"}
var honeypotLetters = []string{"G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q"}

func (h *CSSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	base := h.basePath + "/css"
	switch {
	case p == base || p == base+"/":
		h.servePage(w, r)
	case strings.HasPrefix(p, base+"/img/"):
		h.handleImage(w, r)
	case strings.HasPrefix(p, base+"/done"):
		h.handleDone(w, r)
	default:
		http.NotFound(w, r)
	}
}

// cssTemplateData is passed to templates/css.html.
// CSS and HTML fields use typed wrappers so html/template does not escape them.
type cssTemplateData struct {
	Host          string
	BasePath      string
	DoneURL       string
	KeyframeCSS   template.CSS
	HoneypotCSS   template.CSS
	HoneypotLinks template.HTML
	HoneypotImgs  template.HTML
}

func (h *CSSHandler) servePage(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	sessID, err := randomBase64(16)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	expected := shuffleLetters(sequenceLetters[:h.seqLen])
	h.store.Set("css:"+sessID, &CSSSession{IP: ip, Expected: expected}, h.nonceTTL)
	http.SetCookie(w, &http.Cookie{
		Name: "waf_css", Value: sessID, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 60,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)

	data := h.buildTemplateData(sessID, expected, redirect, r)
	if err := mustTemplate("css.html", tmplCSS).Execute(w, data); err != nil {
		h.log.Error("css: template execute error", "err", err)
	}
	h.log.Debug("css: challenge served", "ip", ip)
}

func (h *CSSHandler) buildTemplateData(sessID string, expected []string, redirect string, r *http.Request) cssTemplateData {
	imgBase := h.basePath + "/css/img/"
	doneURL := h.basePath + "/css/done?s=" + sessID + "&redirect=" + urlPercentEncode(redirect)
	hpLetter := honeypotLetters[rand.IntN(len(honeypotLetters))]

	// Build @keyframes CSS for the image sequence.
	// Percentages are evenly spaced across [0, 100) so each image has the
	// same time slot in the 4-second loop.  The animation runs on ::before
	// (content:url() is spec-compliant on pseudo-elements).
	var kf strings.Builder
	n := len(expected)
	kf.WriteString("@keyframes csswaf{\n")
	for i, img := range expected {
		// Round to nearest integer percent, ensuring we start at 0% and
		// never reach 100% (that would duplicate the 0% frame on loop).
		pct := (i * 100 + n/2) / n
		if i == 0 {
			pct = 0
		}
		kf.WriteString(fmt.Sprintf("  %d%% { content: url('%s%s?s=%s'); }\n", pct, imgBase, img, sessID))
	}
	kf.WriteString("}\n")

	// Honeypot CSS element (fetched via background/content property).
	hpCSS := fmt.Sprintf(".hpot::before{content:url('%s%s?s=%s&from=css')}", imgBase, hpLetter, sessID)

	// Hidden honeypot <a> links (display:none via CSS; JS-disabled crawlers may still fetch).
	var hpLinks strings.Builder
	for _, hp := range honeypotLetters {
		hpLinks.WriteString(fmt.Sprintf(
			`<a href="%s%s?s=%s&from=a_href" class="hpa">x</a>`+"\n",
			imgBase, hp, sessID))
	}

	// Zero-size hidden <img> honeypots.
	var hpImgs strings.Builder
	for _, hp := range honeypotLetters {
		hpImgs.WriteString(fmt.Sprintf(
			`<img src="%s%s?s=%s&from=img_src" style="width:0;height:0;position:absolute;top:-9999px;" loading="lazy">`+"\n",
			imgBase, hp, sessID))
	}

	return cssTemplateData{
		Host:          cleanHost(r),
		BasePath:      h.basePath,
		DoneURL:       doneURL,
		KeyframeCSS:   template.CSS(kf.String()),
		HoneypotCSS:   template.CSS(hpCSS),
		HoneypotLinks: template.HTML(hpLinks.String()),
		HoneypotImgs:  template.HTML(hpImgs.String()),
	}
}

func (h *CSSHandler) handleImage(w http.ResponseWriter, r *http.Request) {
	base := h.basePath + "/css/img/"
	imgID := strings.TrimPrefix(r.URL.Path, base)
	sessID := r.URL.Query().Get("s")
	defer serveTransparentGIF(w)
	if sessID == "" || imgID == "" {
		return
	}
	raw, ok := h.store.Get("css:" + sessID)
	if !ok {
		return
	}
	sess := raw.(*CSSSession)
	if sess.Failed || sess.Validated || sess.IP != extractClientIP(r) {
		if sess.IP != extractClientIP(r) {
			sess.Failed = true
			h.store.Set("css:"+sessID, sess, h.nonceTTL)
		}
		return
	}
	for _, hp := range honeypotLetters {
		if hp == imgID {
			h.log.Info("css: honeypot triggered", "session", sessID[:8], "img", imgID)
			sess.Failed = true
			h.store.Set("css:"+sessID, sess, h.nonceTTL)
			return
		}
	}
	sess.Loaded = append(sess.Loaded, imgID)
	if len(sess.Loaded) >= len(sess.Expected) {
		match := true
		for i := range sess.Loaded {
			if sess.Loaded[i] != sess.Expected[i] {
				match = false
				break
			}
		}
		if match {
			sess.Validated = true
			h.log.Info("css: sequence validated", "session", sessID[:8])
		} else {
			sess.Failed = true
		}
	}
	h.store.Set("css:"+sessID, sess, h.nonceTTL)
}

func (h *CSSHandler) handleDone(w http.ResponseWriter, r *http.Request) {
	sessID := r.URL.Query().Get("s")
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	if sessID == "" {
		if c, err := r.Cookie("waf_css"); err == nil {
			sessID = c.Value
		}
	}
	if sessID == "" {
		errorpage.Write(w, http.StatusForbidden)
		return
	}
	raw, ok := h.store.Get("css:" + sessID)
	if !ok {
		errorpage.Write(w, http.StatusForbidden)
		return
	}
	sess := raw.(*CSSSession)
	if !sess.Validated || sess.Failed {
		h.store.Delete("css:" + sessID)
		http.Redirect(w, r, h.basePath+"/css?redirect="+urlPercentEncode(redirect), http.StatusFound)
		return
	}
	h.store.Delete("css:" + sessID)
	http.SetCookie(w, &http.Cookie{Name: "waf_css", Value: "", Path: "/", MaxAge: -1})
	ip := extractClientIP(r)
	tok := h.tokenMgr.Issue(ip)
	secure := r.Header.Get("X-Forwarded-Proto") == "https"
	w.Header().Set("Set-Cookie", token.CookieHeader(tok, h.tokenMgr.TTL(), secure))
	h.log.Info("css: challenge passed — token issued", "ip", ip)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *CSSHandler) IsValidated(r *http.Request) (string, bool) {
	c, err := r.Cookie("waf_css")
	if err != nil {
		return "", false
	}
	raw, ok := h.store.Get("css:" + c.Value)
	if !ok {
		return "", false
	}
	sess := raw.(*CSSSession)
	return c.Value, sess.Validated && !sess.Failed && sess.IP == extractClientIP(r)
}

func shuffleLetters(in []string) []string {
	cp := make([]string, len(in))
	copy(cp, in)
	for i := len(cp) - 1; i > 0; i-- {
		j := rand.IntN(i + 1)
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}

func serveTransparentGIF(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
		0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
		0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
		0x01, 0x00, 0x3b,
	})
}
