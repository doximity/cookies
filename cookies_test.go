package cookies

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestNewCookieEncryptorRejectsWeakConfig(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		iterations int
		wantErr    string
	}{
		{name: "empty secret", secret: "", iterations: minimumKeyDerivationIterations, wantErr: "missing or blank"},
		{name: "blank secret", secret: "   ", iterations: minimumKeyDerivationIterations, wantErr: "missing or blank"},
		{name: "short secret", secret: strings.Repeat("s", minimumCookieSecretLength-1), iterations: minimumKeyDerivationIterations, wantErr: "at least 32 bytes"},
		{name: "negative iterations", secret: strings.Repeat("s", minimumCookieSecretLength), iterations: -1, wantErr: "zero for the default or at least the minimum"},
		{name: "low iterations", secret: strings.Repeat("s", minimumCookieSecretLength), iterations: 1, wantErr: "zero for the default or at least 1000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewCookieEncryptorWithError(tt.secret, tt.iterations); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewCookieEncryptorPanicsOnWeakConfig(t *testing.T) {
	requirePanicContaining(t, func() {
		NewCookieEncryptor("", minimumKeyDerivationIterations)
	}, "missing or blank")
}

func TestNewCookieEncryptorAcceptsDefaultAndMinimumIterations(t *testing.T) {
	for _, iterations := range []int{0, minimumKeyDerivationIterations} {
		t.Run(fmt.Sprintf("iterations %d", iterations), func(t *testing.T) {
			ce, err := NewCookieEncryptorWithError(strings.Repeat("s", minimumCookieSecretLength), iterations)
			if err != nil {
				t.Fatalf("NewCookieEncryptorWithError returned error: %v", err)
			}

			cookie := &http.Cookie{Name: "session", Value: "value"}
			if err := ce.Encrypt(cookie); err != nil {
				t.Fatalf("Encrypt returned error: %v", err)
			}
			if cookie.Value == "value" {
				t.Fatal("expected encrypted value to differ from plaintext")
			}
			if err := ce.Decrypt(cookie); err != nil {
				t.Fatalf("Decrypt returned error: %v", err)
			}
			if cookie.Value != "value" {
				t.Fatalf("expected decrypted value %q, got %q", "value", cookie.Value)
			}
		})
	}
}

func requirePanicContaining(t *testing.T, f func(), want string) {
	t.Helper()

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("expected panic containing %q", want)
		}
		if !strings.Contains(fmt.Sprint(recovered), want) {
			t.Fatalf("expected panic containing %q, got %v", want, recovered)
		}
	}()

	f()
}
