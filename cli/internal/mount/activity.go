package mount

type ActivityEvent struct {
	Path      string `json:"path"`
	Direction string `json:"direction"`
	Bytes     int64  `json:"bytes"`
	Timestamp int64  `json:"timestamp"`
	Error     string `json:"error,omitempty"`
}
