package detection

// Violation is returned by the detection engine when a rule matches.
// Name and Score are extended fields used by the anomaly scorer.
type Violation struct {
	RuleID  string
	Name    string
	Message string
	Tag     string
	Score   int
}

// MouseEvent represents a single mouse movement sample collected by the fingerprint challenge page
type MouseEvent struct {
	X int `json:"x"`
	Y int `json:"y"`
	T int `json:"t"` // timestamp ms since page load
}

// KeyEvent represents a single keypress event (timing only, no key value).
type KeyEvent struct {
	T int `json:"t"` // timestamp ms since page load
}

// TimingData holds Navigation Timing API values from the browser.
type TimingData struct {
	NavigationStart int64 `json:"navigationStart"`
	LoadEventEnd    int64 `json:"loadEventEnd"`
}
