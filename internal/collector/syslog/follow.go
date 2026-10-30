package syslog

// Follower follows one file with rotation/truncation handling and returns
// complete new lines. Existing content is skipped.
//
// TODO(advanced): extract the tailer into a shared internal/collector/filetail
// package used by both syslog and servicelog.
type Follower struct{ t *tailer }

func NewFollower(path string) *Follower { return &Follower{t: newTailer(path)} }

// ReadNew returns complete lines appended since the last call.
func (f *Follower) ReadNew() []string { return f.t.readNew() }

func (f *Follower) Close() { f.t.close() }
