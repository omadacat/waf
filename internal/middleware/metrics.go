package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reqTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "requests_total",
		Help: "Total HTTP requests.",
	}, []string{"host", "method", "status"})

	reqDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "request_duration_seconds",
		Help:    "Request latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"host"})
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}
func (sr *statusRecorder) Write(b []byte) (int, error) {
	if sr.status == 0 {
		sr.status = http.StatusOK
	}
	return sr.ResponseWriter.Write(b)
}

type Metrics struct{ next http.Handler }

func NewMetrics(next http.Handler) *Metrics { return &Metrics{next: next} }

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	m.next.ServeHTTP(sr, r)
	dur := time.Since(start).Seconds()
	host := r.Host
	reqTotal.WithLabelValues(host, r.Method, strconv.Itoa(sr.status)).Inc()
	reqDuration.WithLabelValues(host).Observe(dur)
}

func MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}
