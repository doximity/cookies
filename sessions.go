package cookies

import (
	"net"
	"net/http"
	"strings"
)

type SessionConstructor func(*http.Request) (Session, error)

type Session interface {
	Validate(*http.Request) error
}

// SessionManager defines the basic interface for different session backends.
type SessionManager interface {
	Current(*http.Request, Session) error
	Update(http.ResponseWriter, *http.Request, Session) error
}

// CookieSessionManager manages session by storing the session data directly into a secure cookie.
type CookieSessionManager struct {
	cm     *SecureCookieManager
	name   string
	domain string
}

// NewCookieSessionManager creates a new cookie-based session manager.
func NewCookieSessionManager(cm *SecureCookieManager, name string, domain string) *CookieSessionManager {
	return &CookieSessionManager{cm, name, domain}
}

// Current fetches the current session from the request cookie, starting one if it doesn't exist.
func (sm *CookieSessionManager) Current(req *http.Request, sess Session) error {
	_, err := sm.cm.Get(req, sm.name, sess)
	return err
}

// Update updates the session with the given struct, replacing the existing session data with it.
func (sm *CookieSessionManager) Update(w http.ResponseWriter, req *http.Request, sess Session) error {
	var (
		err  error
		opts *CookieOptions
	)

	host := req.Host
	if strings.ContainsRune(host, ':') {
		if host, _, err = net.SplitHostPort(req.Host); err != nil {
			return err
		}
	}

	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		opts = &CookieOptions{Path: "/"}
	} else {
		opts = &CookieOptions{Path: "/", Domain: sm.domain, Secure: true}
	}

	_, err = sm.cm.Set(w, sm.name, opts, sess)
	return err
}
