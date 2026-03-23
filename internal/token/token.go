package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const cookieName = "_waf_tok"

type Manager struct {
	secret []byte
	ttl    time.Duration
}

func New(secret string, ttl time.Duration) *Manager {
	return &Manager{secret: []byte(secret), ttl: ttl}
}

func (m *Manager) Issue(ip string) string {
	expiry := strconv.FormatInt(time.Now().Add(m.ttl).Unix(), 10)
	payload := ip + "|" + expiry
	sig := m.sign(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}

func (m *Manager) Validate(tokenStr, ip string) bool {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	payload := string(payloadBytes)
	if !hmac.Equal(sigBytes, m.sign(payload)) {
		return false
	}
	fields := strings.SplitN(payload, "|", 2)
	if len(fields) != 2 || fields[0] != ip {
		return false
	}
	expiryUnix, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() <= expiryUnix
}

func (m *Manager) TTL() time.Duration { return m.ttl }

func CookieName() string { return cookieName }

func CookieHeader(tokenStr string, ttl time.Duration, secure bool) string {
	expiry := time.Now().Add(ttl).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	v := fmt.Sprintf("%s=%s; Path=/; HttpOnly; SameSite=Lax; Expires=%s",
		cookieName, tokenStr, expiry)
	if secure {
		v += "; Secure"
	}
	return v
}

func (m *Manager) sign(payload string) []byte {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(payload))
	return h.Sum(nil)
}
