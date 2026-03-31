package detection

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type Rule struct {
    ID          string   `yaml:"id"`
    Name        string   `yaml:"name"`
    Severity    string   `yaml:"severity"` // critical, high, medium, low
    Targets     []string `yaml:"targets"`
    Pattern     string   `yaml:"pattern"`
    Condition   string   `yaml:"condition"`   // any, all
    Transform   string   `yaml:"transform"`   // none, lowercase, normalize_path, decode_url
    Message     string   `yaml:"message"`
    Tag         string   `yaml:"tag"`
    Action      string   `yaml:"action"`
    re          *regexp.Regexp
}

type DetectionEngine struct {
    rules          []*Rule
    maxBodySize    int64
    enableAnomaly  bool
    anomalyScore   map[string]int // IP -> score
    log            *slog.Logger
}

func (e *DetectionEngine) Inspect(r *http.Request) *Violation {
    // Extract all targets
    targets := e.extractTargets(r)

    // Track score for anomaly detection
    score := 0

    for _, rule := range e.rules {
        matches := 0
        for _, target := range rule.Targets {
            content, ok := targets[target]
            if !ok {
                continue
            }

            // Apply transformations
            content = e.transform(content, rule.Transform)

            if rule.re.MatchString(content) {
                matches++
                if rule.Condition == "any" {
                    break
                }
            }
        }

        // Check if condition satisfied
        satisfied := false
        if rule.Condition == "any" {
            satisfied = matches > 0
        } else { // all
            satisfied = matches == len(rule.Targets)
        }

        if satisfied {
            score += e.getSeverityScore(rule.Severity)

            if rule.Action == "block" {
                return &Violation{
                    RuleID:  rule.ID,
                    Name:    rule.Name,
                    Message: rule.Message,
                    Tag:     rule.Tag,
                    Score:   score,
                }
            }
        }
    }

    // Anomaly detection threshold
    if e.enableAnomaly && score > 50 {
        return &Violation{
            RuleID:  "anomaly-001",
            Name:    "Anomaly Score Threshold Exceeded",
            Message: "Multiple low-severity violations detected",
            Tag:     "anomaly",
            Score:   score,
        }
    }

    return nil
}

func (e *DetectionEngine) extractTargets(r *http.Request) map[string]string {
    targets := make(map[string]string)

    // URI with query
    targets["uri"] = r.URL.RequestURI()
    targets["path"] = r.URL.Path
    targets["query"] = r.URL.RawQuery

    // Method
    targets["method"] = r.Method

    // Headers
    for k, v := range r.Header {
        targets["header:"+k] = strings.Join(v, ", ")
    }
    targets["ua"] = r.Header.Get("User-Agent")
    targets["referer"] = r.Header.Get("Referer")

    // Query parameters individually
    for k, v := range r.URL.Query() {
        targets["param:"+k] = strings.Join(v, ", ")
    }

    // Body (capped size)
    if r.Body != nil {
        body, _ := io.ReadAll(io.LimitReader(r.Body, e.maxBodySize))
        r.Body = io.NopCloser(bytes.NewReader(body))
        targets["body"] = string(body)

        // Try to parse as form data
        if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
            if values, err := url.ParseQuery(string(body)); err == nil {
                for k, v := range values {
                    targets["form:"+k] = strings.Join(v, ", ")
                }
            }
        }
    }

    return targets
}

func (e *DetectionEngine) transform(content, transform string) string {
    switch transform {
    case "lowercase":
        return strings.ToLower(content)
    case "normalize_path":
        // Clean path segments
        parts := strings.Split(content, "/")
        clean := make([]string, 0, len(parts))
        for _, part := range parts {
            if part == ".." || part == "." {
                continue
            }
            clean = append(clean, part)
        }
        return strings.Join(clean, "/")
    case "decode_url":
        if decoded, err := url.QueryUnescape(content); err == nil {
            return decoded
        }
        return content
    default:
        return content
    }
}

func (e *DetectionEngine) getSeverityScore(severity string) int {
    switch severity {
    case "critical":
        return 100
    case "high":
        return 50
    case "medium":
        return 25
    case "low":
        return 10
    default:
        return 0
    }
}

// New constructs a DetectionEngine from a list of rules.
func New(rules []*Rule, maxBodySize int64, enableAnomaly bool, log *slog.Logger) (*DetectionEngine, error) {
	e := &DetectionEngine{
		rules:         make([]*Rule, 0, len(rules)),
		maxBodySize:   maxBodySize,
		enableAnomaly: enableAnomaly,
		anomalyScore:  make(map[string]int),
		log:           log,
	}
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			log.Warn("detection: invalid rule pattern — skipping", "id", r.ID, "err", err)
			continue
		}
		r.re = re
		if r.Condition == "" {
			r.Condition = "any"
		}
		if r.Action == "" {
			r.Action = "block"
		}
		e.rules = append(e.rules, r)
	}
	log.Info("detection engine ready", "rules", len(e.rules))
	return e, nil
}
