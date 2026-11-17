package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newManager(t *testing.T, secure bool) *Manager {
	t.Helper()
	m, err := New("test-secret", secure)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIssueAndVerify(t *testing.T) {
	m := newManager(t, false)
	w := httptest.NewRecorder()
	id, err := m.Issue(w)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := hex.DecodeString(id); err != nil || len(data) != 16 {
		t.Fatalf("user ID is not 128 bits: %q", id)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieName || c.Path != "/" || !c.HttpOnly || c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge <= 0 {
		t.Fatalf("unexpected cookie settings: %+v", c)
	}
	// Independently verify HMAC instead of only round-tripping our own parser.
	h := hmac.New(sha256.New, []byte("test-secret"))
	h.Write([]byte(id))
	if want := id + ":" + hex.EncodeToString(h.Sum(nil)); c.Value != want {
		t.Fatalf("cookie = %q, want %q", c.Value, want)
	}
	if got, err := m.Parse(c.Value); err != nil || got != id {
		t.Fatalf("Parse = %q, %v", got, err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	if got, err := m.User(w, r); err != nil || got != id || len(w.Result().Cookies()) != 0 {
		t.Fatalf("valid cookie not reused: ID=%q, error=%v", got, err)
	}
	other, _ := New("different-secret", false)
	if _, err := other.Parse(c.Value); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("different key accepted: %v", err)
	}
}

func TestParseRejectsTamperingAndMalformedCookies(t *testing.T) {
	m := newManager(t, false)
	w := httptest.NewRecorder()
	_, err := m.Issue(w)
	if err != nil {
		t.Fatal(err)
	}
	valid := w.Result().Cookies()[0].Value
	id, signature, _ := strings.Cut(valid, ":")
	cases := []struct {
		name  string
		value string
		want  error
	}{
		{"empty", "", ErrMalformedCookie},
		{"no separator", "user", ErrMalformedCookie},
		{"no ID", ":" + signature, ErrMalformedCookie},
		{"no signature", id + ":", ErrMalformedCookie},
		{"extra separator", valid + ":extra", ErrMalformedCookie},
		{"invalid ID", "bad id:" + signature, ErrMalformedCookie},
		{"oversized ID", strings.Repeat("a", 129) + ":" + signature, ErrMalformedCookie},
		{"changed ID", "someone-else:" + signature, ErrInvalidSignature},
		{"changed signature", id + ":" + strings.Repeat("0", 64), ErrInvalidSignature},
		{"nonhex signature", id + ":zz", ErrInvalidSignature},
		{"short signature", id + ":aa", ErrInvalidSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := m.Parse(tc.value); got != "" || !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %q, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestUserIssuesNewIdentity(t *testing.T) {
	m := newManager(t, true)
	seen := make(map[string]bool)
	for _, value := range []string{"", "attacker:" + strings.Repeat("0", 64)} {
		r := httptest.NewRequest(http.MethodGet, "https://short.test/", nil)
		if value != "" {
			r.AddCookie(&http.Cookie{Name: CookieName, Value: value})
		}
		w := httptest.NewRecorder()
		id, err := m.User(w, r)
		if err != nil || id == "" || id == "attacker" || seen[id] {
			t.Fatalf("new identity = %q, %v", id, err)
		}
		seen[id] = true
		if cookies := w.Result().Cookies(); len(cookies) != 1 || !cookies[0].Secure {
			t.Fatal("HTTPS cookie must have Secure")
		}
	}
}

func TestEntropyFailure(t *testing.T) {
	m := newManager(t, false)
	m.random = strings.NewReader("")
	w := httptest.NewRecorder()
	if _, err := m.Issue(w); !errors.Is(err, io.EOF) {
		t.Fatalf("entropy error = %v", err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("cookie issued despite failed randomness")
	}
}

func TestEmptySigningKey(t *testing.T) {
	if _, err := New("", false); err == nil {
		t.Fatal("empty secret accepted")
	}
}

func FuzzParse(f *testing.F) {
	m, _ := New("fuzz-secret", false)
	f.Add("")
	f.Add("user:abcd")
	f.Add(":")
	f.Fuzz(func(t *testing.T, value string) {
		id, err := m.Parse(value)
		if err == nil && id == "" {
			t.Fatal("empty ID accepted")
		}
	})
}
