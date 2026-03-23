package challenges

import (
	"fmt"
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
	fmt.Fprint(w, h.buildPage(sessID, expected, redirect))
	h.log.Debug("css: challenge served", "ip", ip)
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

func (h *CSSHandler) buildPage(sessID string, expected []string, redirect string) string {
	base := h.basePath + "/css"
	imgBase := base + "/img/"
	doneURL := base + "/done?s=" + sessID + "&redirect=" + urlPercentEncode(redirect)
	cssHoneypot := honeypotLetters[rand.IntN(len(honeypotLetters))]

	var kf strings.Builder
	for i, img := range expected {
		kf.WriteString(fmt.Sprintf("  %d%% { content: url('%s%s?s=%s'); }\n",
			i*100/len(expected), imgBase, img, sessID))
	}

	var hpLinks, hpImgs strings.Builder
	for _, hp := range honeypotLetters {
		hpLinks.WriteString(`<a href="` + imgBase + hp + `?s=` + sessID + `&from=a_href" class="hpa">x</a>` + "\n")
		hpImgs.WriteString(`<img src="` + imgBase + hp + `?s=` + sessID + `&from=img_src" style="width:0;height:0;position:absolute;top:-9999px;" loading="lazy">` + "\n")
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5.5; url=` + doneURL + `">
<title>Checking your browser…</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{width:100%;background:#fff;color:#000;
  font-family:"Noto Serif","Source Serif",Times New Roman,serif;line-height:1.75}
html,body{min-height:100vh}
body{display:flex;margin:0 auto;max-width:83vw;flex-wrap:wrap;flex-direction:column;justify-content:space-between}
header{margin:10vh 0 0;padding-bottom:1em;border-bottom:5px solid #328c60}
header a{font-size:1.5em;font-weight:bold;color:#000;text-decoration:none}
main{display:flex;margin:1em auto;min-width:70vw;flex-wrap:wrap;flex-direction:column;padding:1em}
h1{line-height:1.5;font-size:1.625em;margin-top:1em;margin-bottom:.5em}
p{margin:.5em 0}
a{color:#36c}
em,footer{color:#777;font-style:normal}
footer{margin:0 0 10vh;padding-top:1em;border-top:1px solid #eaecf0;font-size:.9em}
.hpot{content:url('` + imgBase + cssHoneypot + `?s=` + sessID + `&from=css')}
@keyframes csswaf{
` + kf.String() + `}
.csswaf-hidden{width:1px;height:1px;position:absolute;top:0;left:0;animation:csswaf 3.5s linear forwards}
.hpa{display:none;width:0;height:0;position:absolute;top:-9898px;left:-9898px}
.spin{display:inline-block;width:40px;height:40px;border:4px solid #eee;border-top-color:#328c60;border-radius:50%;animation:sp .8s linear infinite;margin:1em 0}
@keyframes sp{to{transform:rotate(360deg)}}
@media(prefers-color-scheme:dark){html{background:#121212;color:#e0e0e0}header{border-bottom-color:#2d7353}header a{color:#e0e0e0}footer{border-top-color:#333;color:#aaa}}
</style>
</head>
<body>
<header><a href="/">Checking your browser</a></header>
<div class="hpot" aria-hidden="true"></div>
<div class="csswaf-hidden" aria-hidden="true"></div>
`)
	b.WriteString(hpLinks.String())
	b.WriteString(`<main>
  <h1>Just a moment…<em> (NoJS challenge)</em></h1>
  <p>Verifying your browser without JavaScript. Completes in ~5 seconds.</p>
  <div class="spin" aria-hidden="true"></div>
`)
	b.WriteString(hpImgs.String())
	b.WriteString(`</main>
<footer><p>Protected by <a href="https://git.omada.cafe/atf/waf" rel="noopener">WAF</a></p></footer>
</body></html>`)
	return b.String()
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
