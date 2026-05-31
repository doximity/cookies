package cookies

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testSession struct {
	UserID string `json:"user_id"`
}

func (s *testSession) Validate(*http.Request) error {
	return nil
}

func newTestSecureCookieManager(t *testing.T) *SecureCookieManager {
	t.Helper()

	return &SecureCookieManager{
		Encryptor: NewCookieEncryptor(strings.Repeat("s", 32), 1000),
		Encoder:   JSONCookieEncoder{},
	}
}

func TestSecureCookieManagerSetAppliesSecureDefaults(t *testing.T) {
	cm := newTestSecureCookieManager(t)

	tests := []struct {
		name string
		opts *CookieOptions
	}{
		{name: "nil options", opts: nil},
		{name: "empty options", opts: &CookieOptions{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			cookie, err := cm.Set(recorder, "session", tt.opts, map[string]string{"user_id": "123"})
			if err != nil {
				t.Fatalf("Set returned error: %v", err)
			}

			if !cookie.HttpOnly {
				t.Fatal("expected HttpOnly default")
			}
			if !cookie.Secure {
				t.Fatal("expected Secure default")
			}
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("expected SameSite=Lax default, got %v", cookie.SameSite)
			}
			if cookie.Path != "/" {
				t.Fatalf("expected Path=/ default, got %q", cookie.Path)
			}

			setCookie := recorder.Header().Get("Set-Cookie")
			for _, want := range []string{"HttpOnly", "Secure", "SameSite=Lax", "Path=/"} {
				if !strings.Contains(setCookie, want) {
					t.Fatalf("expected Set-Cookie to contain %q, got %q", want, setCookie)
				}
			}
		})
	}
}

func TestSecureCookieManagerSetPreservesExplicitSafeOptions(t *testing.T) {
	cm := newTestSecureCookieManager(t)
	opts := &CookieOptions{
		Domain:   "example.com",
		Path:     "/app",
		HTTPOnly: true,
		Secure:   true,
		MaxAge:   5 * time.Second,
		SameSite: http.SameSiteStrictMode,
	}
	recorder := httptest.NewRecorder()

	cookie, err := cm.Set(recorder, "session", opts, map[string]string{"user_id": "123"})
	if err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	if cookie.Domain != opts.Domain {
		t.Fatalf("expected domain %q, got %q", opts.Domain, cookie.Domain)
	}
	if cookie.Path != opts.Path {
		t.Fatalf("expected path %q, got %q", opts.Path, cookie.Path)
	}
	if cookie.MaxAge != int(opts.MaxAge.Seconds()) {
		t.Fatalf("expected MaxAge %d, got %d", int(opts.MaxAge.Seconds()), cookie.MaxAge)
	}
	if cookie.SameSite != opts.SameSite {
		t.Fatalf("expected SameSite %v, got %v", opts.SameSite, cookie.SameSite)
	}
}

func TestCookieSessionManagerUpdateUsesSecureDefaultCookieOptions(t *testing.T) {
	cm := newTestSecureCookieManager(t)
	sm := NewCookieSessionManager(cm, "session", nil)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if err := sm.Update(recorder, req, &testSession{UserID: "123"}); err != nil {
		t.Fatalf("Update returned error: %v", err)
	}

	setCookie := recorder.Header().Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(setCookie, want) {
			t.Fatalf("expected Set-Cookie to contain %q, got %q", want, setCookie)
		}
	}
}
