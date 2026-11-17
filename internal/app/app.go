// Package app provides the URL shortener HTTP API.
package app

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"shortener/internal/auth"
	"shortener/internal/storage"
)

const (
	DefaultBaseURL = "http://localhost:8080"
	// DefaultSecret is permitted for this educational project only.
	DefaultSecret = "super-secret-key"
	maxBodyBytes  = 1 << 20
)

type Config struct {
	BaseURL   string
	SecretKey string
}

type App struct {
	baseURL string
	auth    *auth.Manager
	store   *storage.Memory
}

type UserURL struct {
	ShortURL    string `json:"short_url"`
	OriginalURL string `json:"original_url"`
}

func New(config Config) (*App, error) {
	if config.BaseURL == "" {
		config.BaseURL = DefaultBaseURL
	}
	if config.SecretKey == "" {
		config.SecretKey = DefaultSecret
	}
	u, err := parseHTTPURL(config.BaseURL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(config.BaseURL, "#") || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("base URL must be an absolute HTTP(S) origin without credentials, query, or fragment")
	}
	manager, err := auth.New(config.SecretKey, u.Scheme == "https")
	if err != nil {
		return nil, err
	}
	return &App{
		baseURL: strings.TrimSuffix(config.BaseURL, "/"),
		auth:    manager,
		store:   storage.NewMemory(),
	}, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The user list and Set-Cookie responses must not be cached by intermediaries.
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/api/shorten":
		if requireMethod(w, r, http.MethodPost) {
			a.shorten(w, r)
		}
	case "/api/user/urls":
		if requireMethod(w, r, http.MethodGet) {
			a.list(w, r)
		}
	default:
		id := strings.TrimPrefix(r.URL.Path, "/")
		if id == "" || strings.Contains(id, "/") {
			writeError(w, http.StatusNotFound, "short URL not found")
			return
		}
		if requireMethod(w, r, http.MethodGet) {
			a.redirect(w, r, id)
		}
	}
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func (a *App) shorten(w http.ResponseWriter, r *http.Request) {
	// A missing Content-Type is tolerated for simple clients; an explicit wrong
	// media type is rejected. Parameters such as charset=utf-8 are accepted.
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input struct {
		URL string `json:"url"`
	}
	if err := decoder.Decode(&input); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeDecodeError(w, err)
		return
	}
	if _, err := parseHTTPURL(input.URL); err != nil {
		writeError(w, http.StatusBadRequest, "url must be an absolute HTTP(S) URL with a valid host")
		return
	}
	userID, err := a.auth.User(w, r)
	if errors.Is(err, auth.ErrMalformedCookie) {
		userID, err = a.auth.Issue(w)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not identify user")
		return
	}
	link, err := a.store.Add(userID, input.URL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save URL")
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		Result string `json:"result"`
	}{Result: a.baseURL + "/" + link.ID})
}

func (a *App) redirect(w http.ResponseWriter, r *http.Request, id string) {
	originalURL, ok := a.store.Resolve(id)
	if !ok {
		writeError(w, http.StatusNotFound, "short URL not found")
		return
	}
	http.Redirect(w, r, originalURL, http.StatusTemporaryRedirect)
}

func (a *App) list(w http.ResponseWriter, r *http.Request) {
	userID, err := a.auth.User(w, r)
	if errors.Is(err, auth.ErrMalformedCookie) {
		writeError(w, http.StatusUnauthorized, "cookie has no user ID or has an invalid format")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not identify user")
		return
	}
	links := a.store.List(userID)
	if len(links) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	result := make([]UserURL, len(links))
	for i, link := range links {
		result[i] = UserURL{ShortURL: a.baseURL + "/" + link.ID, OriginalURL: link.OriginalURL}
	}
	writeJSON(w, http.StatusOK, result)
}

func parseHTTPURL(raw string) (*url.URL, error) {
	if strings.ContainsFunc(raw, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) {
		return nil, errors.New("URL contains whitespace or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || strings.ContainsAny(u.Host, "\\") {
		return nil, errors.New("invalid URL scheme or host")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid URL port")
		}
	}
	return u, nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds 1 MiB")
		return
	}
	writeError(w, http.StatusBadRequest, "body must contain exactly one JSON object with a string url field")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	// Marshal before sending headers so an encoding failure can return 500.
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "could not encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// A network write failure cannot be repaired after the response has started.
	_, _ = w.Write(append(data, '\n'))
}
