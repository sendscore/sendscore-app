// Package budget bounds the memory the receiver and uploads may use for
// messages at once, across both.
package budget

import "sync/atomic"

// PerByte is how much memory a message costs while it is read and checked,
// per byte of the message. It was measured with a 24 MB base64 HTML message,
// whose heap peaked about 220 MB above the baseline. ReadPerByte of that is
// charged as it arrives, which covers the copy made when it is stamped, and
// the rest when its checks start, so a body that stalls holds only the first.
const (
	PerByte     = 10
	ReadPerByte = 2
)

// Budget is a limit on bytes in use. It is safe for concurrent use.
type Budget struct {
	limit int64
	used  atomic.Int64
}

// New makes a budget of limit bytes.
func New(limit int64) *Budget { return &Budget{limit: limit} }

// Take charges n bytes, or reports false and charges nothing when that goes
// over the limit.
func (b *Budget) Take(n int64) bool {
	if b.used.Add(n) > b.limit {
		b.used.Add(-n)
		return false
	}
	return true
}

// Release gives back n bytes.
func (b *Budget) Release(n int64) { b.used.Add(-n) }
