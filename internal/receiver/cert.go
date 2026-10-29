package receiver

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// certCheckEvery is how often CertLoader looks for a renewed certificate.
const certCheckEvery = time.Minute

// CertLoader serves the STARTTLS certificate from a pair of files and
// reloads it when either file changes, so a renewal (such as Let's Encrypt
// every 60 to 90 days) takes effect without a restart. It looks at the files
// at most once a minute, and keeps the certificate it has when a reload
// fails, such as halfway through a renewal writing the files.
type CertLoader struct {
	certFile, keyFile string
	now               func() time.Time
	onError           func(error)

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   [2]time.Time // modification times of the files loaded
	checked time.Time
}

// NewCertLoader loads the pair once, failing when it cannot. onError, when
// set, hears about later reloads that fail.
func NewCertLoader(certFile, keyFile string, onError func(error)) (*CertLoader, error) {
	l := &CertLoader{certFile: certFile, keyFile: keyFile, now: time.Now, onError: onError}
	if err := l.load(); err != nil {
		return nil, err
	}
	l.checked = l.now()
	return l, nil
}

func (l *CertLoader) modTimes() ([2]time.Time, error) {
	var out [2]time.Time
	for i, f := range []string{l.certFile, l.keyFile} {
		st, err := os.Stat(f)
		if err != nil {
			return out, err
		}
		out[i] = st.ModTime()
	}
	return out, nil
}

// load reads the pair. l.mu is held, or l is not shared yet.
func (l *CertLoader) load() error {
	stamp, err := l.modTimes()
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return err
	}
	l.cert, l.stamp = &pair, stamp
	return nil
}

// GetCertificate is for tls.Config.GetCertificate.
func (l *CertLoader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := l.now(); now.Sub(l.checked) >= certCheckEvery {
		l.checked = now
		if stamp, err := l.modTimes(); err == nil && stamp != l.stamp {
			if err := l.load(); err != nil && l.onError != nil {
				l.onError(err)
			}
		}
	}
	return l.cert, nil
}
