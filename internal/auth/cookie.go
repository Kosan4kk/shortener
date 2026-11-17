// Package auth identifies anonymous users with HMAC-signed cookies.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const CookieName = "user_id"

var (
	ErrMalformedCookie  = errors.New("cookie has no user ID or has an invalid format")
	ErrInvalidSignature = errors.New("invalid cookie signature")
)

// Manager is safe for concurrent use; its configuration is immutable.
type Manager struct {
	key    []byte
	secure bool
	random io.Reader
}

func New(secret string, secure bool) (*Manager, error) {
	if secret == "" {
		return nil, errors.New("cookie signing key must not be empty")
	}
	return &Manager{key: []byte(secret), secure: secure, random: rand.Reader}, nil
}

func (m *Manager) signature(userID string) []byte {
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte(userID))
	return h.Sum(nil)
}

// Parse distinguishes missing identity/invalid structure from a bad signature.
func (m *Manager) Parse(value string) (string, error) {
	userID, signature, ok := strings.Cut(value, ":")
	if !ok || userID == "" || signature == "" || strings.Contains(signature, ":") || len(userID) > 128 {
		return "", ErrMalformedCookie
	}
	for _, c := range userID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", ErrMalformedCookie
		}
	}
	actual, err := hex.DecodeString(signature)
	if err != nil || !hmac.Equal(m.signature(userID), actual) {
		return "", ErrInvalidSignature
	}
	return userID, nil
}

// Issue creates a cryptographically random 128-bit user ID.
func (m *Manager) Issue(w http.ResponseWriter) (string, error) {
	var data [16]byte
	if _, err := io.ReadFull(m.random, data[:]); err != nil {
		return "", fmt.Errorf("generate user ID: %w", err)
	}
	userID := hex.EncodeToString(data[:])
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    userID + ":" + hex.EncodeToString(m.signature(userID)),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	})
	return userID, nil
}

// User reuses a valid identity or replaces an absent/untrusted signature.
// Structural errors are returned so each endpoint can apply its API contract.
func (m *Manager) User(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, err := r.Cookie(CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return m.Issue(w)
	}
	if err != nil {
		return "", fmt.Errorf("read cookie: %w", err)
	}
	userID, err := m.Parse(cookie.Value)
	if errors.Is(err, ErrInvalidSignature) {
		return m.Issue(w)
	}
	return userID, err
}
