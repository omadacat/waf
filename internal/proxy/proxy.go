package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"git.omada.cafe/atf/waf/internal/errorpage"
	"time"
)

type Router struct {
	proxies map[string]*httputil.ReverseProxy
	log     *slog.Logger
}

func New(backends map[string]string, log *slog.Logger) (*Router, error) {
	r := &Router{proxies: make(map[string]*httputil.ReverseProxy), log: log}
	for host, rawURL := range backends {
		target, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("invalid backend URL for %q: %w", host, err)
		}
		r.proxies[host] = buildProxy(target, log)
		log.Info("proxy: registered backend", "host", host, "target", rawURL)
	}
	return r, nil
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	p, ok := r.proxies[host]
	if !ok {
		r.log.Warn("proxy: no backend for host", "host", host)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	p.ServeHTTP(w, req)
}

func buildProxy(target *url.URL, log *slog.Logger) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 100, MaxIdleConnsPerHost: 20,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
	}
	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			if req.Header.Get("X-Forwarded-Host") == "" {
				req.Header.Set("X-Forwarded-Host", req.Host)
			}
			if req.Header.Get("X-Forwarded-Proto") == "" {
				req.Header.Set("X-Forwarded-Proto", "https")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("X-Powered-By")
			resp.Header.Del("Server")
			if resp.Header.Get("X-Content-Type-Options") == "" {
				resp.Header.Set("X-Content-Type-Options", "nosniff")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if strings.Contains(err.Error(), "context canceled") {
				return
			}
			log.Error("proxy: backend error", "err", err, "host", r.Host, "path", r.URL.Path)
			errorpage.Write(w, http.StatusBadGateway)
		},
	}
}
