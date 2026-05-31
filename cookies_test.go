package cookies

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testSession struct {
	UserID      string `json:"user_id"`
	validateErr error
	validateHit int
}

func (s *testSession) Validate(*http.Request) error {
	s.validateHit++
	return s.validateErr
}

func newTestSecureCookieManager(t *testing.T) *SecureCookieManager {
	t.Helper()

	return &SecureCookieManager{
		Encryptor: NewCookieEncryptor(strings.Repeat("s", 32), 1000),
		Encoder:   JSONCookieEncoder{},
	}
}

func TestCookieSessionManagerCurrentEnforcesSessionValidate(t *testing.T) {
	cm := newTestSecureCookieManager(t)
	sm := NewCookieSessionManager(cm, "session", nil)
	req := requestWithUpdatedSession(t, sm, &testSession{UserID: "123"})
	validateErr := errors.New("invalid session")
	decoded := &testSession{validateErr: validateErr}

	err := sm.Current(req, decoded)
	if !errors.Is(err, validateErr) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if decoded.validateHit != 1 {
		t.Fatalf("expected Validate to be called once, got %d", decoded.validateHit)
	}
	if decoded.UserID != "123" {
		t.Fatalf("expected decoded user ID %q, got %q", "123", decoded.UserID)
	}
}

func TestCookieSessionManagerCurrentReturnsNilWhenSessionValidates(t *testing.T) {
	cm := newTestSecureCookieManager(t)
	sm := NewCookieSessionManager(cm, "session", nil)
	req := requestWithUpdatedSession(t, sm, &testSession{UserID: "123"})
	decoded := &testSession{}

	if err := sm.Current(req, decoded); err != nil {
		t.Fatalf("Current returned error: %v", err)
	}
	if decoded.validateHit != 1 {
		t.Fatalf("expected Validate to be called once, got %d", decoded.validateHit)
	}
	if decoded.UserID != "123" {
		t.Fatalf("expected decoded user ID %q, got %q", "123", decoded.UserID)
	}
}

func requestWithUpdatedSession(t *testing.T, sm *CookieSessionManager, sess Session) *http.Request {
	t.Helper()

	recorder := httptest.NewRecorder()
	writeReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := sm.Update(recorder, writeReq, sess); err != nil {
		t.Fatalf("Update returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range recorder.Result().Cookies() {
		req.AddCookie(cookie)
	}

	return req
}
