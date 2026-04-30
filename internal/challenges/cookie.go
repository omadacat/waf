package challenges

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/token"
)

// CookieChallenge is a zero-computation pre-filter that sits before JS PoW.
//
// Round 1 — new visitor, no cookie:
//   Issue a signed short-lived cookie (waf_pre) and redirect to the same URL.
//   Any HTTP client that can't follow redirects or store cookies fails here.
//   This silently eliminates curl, wget, Python-requests without a cookie jar,
//   and most scrapy/mechanize bots with a single round trip, zero CPU spent.
//
// Round 2 — visitor returns with cookie:
//   Validate the HMAC signature and expiry.  If valid, promote to a full WAF
//   token and serve the request.  If invalid or expired, restart from round 1.
//
// The signed cookie binds to the client IP so it cannot be forwarded to another
// machine and replayed.
type CookieChallenge struct {
	secret   []byte
	tokenMgr *token.Manager
}

const cookiePreName = "_waf_pre"
const cookiePreTTL  = 5 * time.Minute

func NewCookieChallenge(secret string, tm *token.Manager) *CookieChallenge {
	return &CookieChallenge{secret: []byte(secret), tokenMgr: tm}
}

// Handle is the http.HandlerFunc used by the Dispatcher for this challenge type.
// It is called only when sessionMW has determined the client has no valid token.
func (cc *CookieChallenge) Handle(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)
	redirect := r.URL.RequestURI()

	if c, err := r.Cookie(cookiePreName); err == nil {
		if cc.validateCookie(c.Value, ip) {
			// Cookie valid — promote to full token and send to destination.
			tok := cc.tokenMgr.Issue(ip)
			secure := r.Header.Get("X-Forwarded-Proto") == "https"
			http.SetCookie(w, &http.Cookie{
				Name: cookiePreName, Value: "", Path: "/", MaxAge: -1,
			})
			w.Header().Set("Set-Cookie", token.CookieHeader(tok, cc.tokenMgr.TTL(), secure))
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		// Bad/expired cookie — clear it and re-issue.
		http.SetCookie(w, &http.Cookie{
			Name: cookiePreName, Value: "", Path: "/", MaxAge: -1,
		})
	}

	// Issue new pre-challenge cookie and redirect.
	val := cc.issueCookie(ip)
	http.SetCookie(w, &http.Cookie{
		Name:     cookiePreName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cookiePreTTL.Seconds()),
	})
	// Use 307 to preserve the HTTP method on redirect.
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

// issueCookie returns a signed cookie value: hex(expiry)|hex(hmac).
func (cc *CookieChallenge) issueCookie(ip string) string {
	expiry := time.Now().Add(cookiePreTTL).Unix()
	payload := signPayload(ip, expiry)
	sig := cc.sign(payload)
	return hex.EncodeToString([]byte(payload)) + "." + hex.EncodeToString(sig)
}

// validateCookie checks the HMAC and expiry of a pre-challenge cookie value.
func (cc *CookieChallenge) validateCookie(val, ip string) bool {
	parts := strings.SplitN(val, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sigBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	payload := string(payloadBytes)
	if !hmac.Equal(sigBytes, cc.sign(payload)) {
		return false
	}
	// Payload: "ip|expiry"
	idx := strings.LastIndex(payload, "|")
	if idx < 0 {
		return false
	}
	if payload[:idx] != ip {
		return false
	}
	var expiry int64
	_, err = nScanf(payload[idx+1:], &expiry)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}
	return true
}

func signPayload(ip string, expiry int64) string {
	return ip + "|" + int64str(expiry)
}

func (cc *CookieChallenge) sign(payload string) []byte {
	h := hmac.New(sha256.New, cc.secret)
	h.Write([]byte(payload))
	return h.Sum(nil)
}

// tiny helpers to avoid fmt import
func int64str(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func nScanf(s string, n *int64) (int, error) {
	var v int64
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &cookieParseError{}
		}
		v = v*10 + int64(c-'0')
	}
	if neg {
		v = -v
	}
	*n = v
	return len(s), nil
}

type cookieParseError struct{}
func (e *cookieParseError) Error() string { return "parse error" }
