package cookies

import "net/http"

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
	cm   *SecureCookieManager
	name string
	opts *CookieOptions
}

// NewCookieSessionManager creates a new cookie-based session manager.
func NewCookieSessionManager(cm *SecureCookieManager, name string, opts *CookieOptions) *CookieSessionManager {
	return &CookieSessionManager{cm, name, opts}
}

// Current fetches the current session from the request cookie, starting one if it doesn't exist.
func (sm *CookieSessionManager) Current(req *http.Request, sess Session) error {
	_, err := sm.cm.Get(req, sm.name, sess)
	return err
}

// Update updates the session with the given struct, replacing the existing session data with it.
func (sm *CookieSessionManager) Update(w http.ResponseWriter, req *http.Request, sess Session) error {
	_, err := sm.cm.Set(w, sm.name, sm.opts, sess)
	return err
}
