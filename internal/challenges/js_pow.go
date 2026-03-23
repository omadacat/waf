package challenges

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
)

type JSHandler struct {
	store      *store.Store
	tokenMgr   *token.Manager
	nonceTTL   time.Duration
	difficulty int
	basePath   string
	log        *slog.Logger
}

func NewJSHandler(s *store.Store, tm *token.Manager, nonceTTL time.Duration, difficulty int, basePath string, log *slog.Logger) *JSHandler {
	return &JSHandler{
		store:      s,
		tokenMgr:   tm,
		nonceTTL:   nonceTTL,
		difficulty: difficulty,
		basePath:   strings.TrimRight(basePath, "/"),
		log:        log,
	}
}

func (h *JSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serve(w, r)
	case http.MethodPost:
		h.verify(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *JSHandler) serve(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	nonce := randomHexStr(16)
	h.store.Set("js:"+nonce, ip, h.nonceTTL)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, jsChallengePage(nonce, h.difficulty, redirect, h.basePath))
	h.log.Debug("js: challenge served", "ip", ip)
}

func (h *JSHandler) verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	nonce := r.FormValue("nonce")
	answer := r.FormValue("answer")
	redirect := r.FormValue("redirect")
	if redirect == "" {
		redirect = "/"
	}
	ip := extractClientIP(r)

	storedIP, ok := h.store.Get("js:" + nonce)
	if !ok {
		http.Error(w, "Challenge expired — reload", http.StatusBadRequest)
		return
	}
	if storedIP.(string) != ip {
		errorpage.Write(w, http.StatusForbidden)
		return
	}
	h.store.Delete("js:" + nonce)

	hash := sha256.Sum256([]byte(nonce + answer))
	if !meetsHashDifficulty(hash[:], h.difficulty) {
		h.log.Warn("js: invalid solution", "ip", ip)
		errorpage.Write(w, http.StatusForbidden)
		return
	}

	tok := h.tokenMgr.Issue(ip)
	secure := r.Header.Get("X-Forwarded-Proto") == "https"
	w.Header().Set("Set-Cookie", token.CookieHeader(tok, h.tokenMgr.TTL(), secure))
	h.log.Info("js: challenge passed — token issued", "ip", ip)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func jsChallengePage(nonce string, difficulty int, redirect, basePath string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser…</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{width:100%%;background:#fff;color:#000;font-family:"Noto Serif","Source Serif",Times New Roman,serif;line-height:1.75}
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
.prog{font-family:monospace;color:#328c60;font-size:.9em}
.spin{display:inline-block;width:40px;height:40px;border:4px solid #eee;border-top-color:#328c60;border-radius:50%%;animation:sp .8s linear infinite;margin:1em 0}
@keyframes sp{to{transform:rotate(360deg)}}
noscript p{color:#c00;margin-top:1em}
@media(prefers-color-scheme:dark){html{background:#121212;color:#e0e0e0}header{border-bottom-color:#2d7353}header a{color:#e0e0e0}footer{border-top-color:#333;color:#aaa}}
</style>
</head>
<body>
<header><a href="/">Checking your browser</a></header>
<main>
  <div class="spin" id="spin"></div>
  <h1>Just a moment…<em> (JS challenge)</em></h1>
  <p>Completing a brief proof-of-work to verify you are human.</p>
  <p class="prog" id="prog">Initialising…</p>
  <noscript><p>JavaScript is disabled. <a href="%s/css?redirect=%s">Use the no-JS challenge.</a></p></noscript>
</main>
<footer><p>Protected by <a href="https://git.omada.cafe/atf/waf" rel="noopener">WAF</a></p></footer>
<script>
"use strict";
const nonce = '%s';
const difficulty = %d;
const redirect = '%s';
const base = '%s';
const prog = document.getElementById('prog');

async function sha256(message) {
    const msgUint8 = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = new Uint8Array(hashBuffer);
    return Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
}

function leadingZeroBits(hex) {
    let bits = 0;
    for (let i = 0; i < hex.length; i++) {
        const nibble = parseInt(hex[i], 16);
        if (nibble === 0) {
            bits += 4;
        } else {
            if (nibble < 2) bits += 3;
            else if (nibble < 4) bits += 2;
            else if (nibble < 8) bits += 1;
            break;
        }
    }
    return bits;
}

async function solve() {
    let counter = 0;
    const batch = 2000;
    while (true) {
        for (let end = counter + batch; counter < end; counter++) {
            const input = nonce + String(counter);
            const hashHex = await sha256(input);
            if (leadingZeroBits(hashHex) >= difficulty) {
                prog.textContent = 'Verified! Redirecting…';
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = base + '/verify-js';
                [['nonce', nonce], ['answer', String(counter)], ['redirect', redirect]]
                    .forEach(([name, value]) => {
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = name;
                        input.value = value;
                        form.appendChild(input);
                    });
                document.body.appendChild(form);
                form.submit();
                return;
            }
        }
        prog.textContent = 'Checked ' + counter.toLocaleString() + ' candidates…';
        await new Promise(resolve => setTimeout(resolve, 0));
    }
}

solve().catch(err => {
    prog.textContent = 'Error: ' + err;
    console.error(err);
});
</script>
</body></html>`,
		basePath, urlPercentEncode(redirect),
		nonce, difficulty, redirect, basePath)
}
