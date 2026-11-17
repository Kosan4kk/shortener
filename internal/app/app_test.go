package app_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"shortener/internal/app"
	"shortener/internal/auth"
)

func newApp(t *testing.T) *app.App {
	t.Helper()
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func request(a http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func shorten(t *testing.T, a http.Handler, original string, cookie *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	data, err := json.Marshal(map[string]string{"url": original})
	if err != nil {
		t.Fatal(err)
	}
	w := request(a, http.MethodPost, "/api/shorten", string(data), cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("shorten status = %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatal("missing JSON content type")
	}
	var result struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Result, app.DefaultBaseURL+"/") {
		t.Fatalf("unexpected short URL: %q", result.Result)
	}
	if cookie == nil {
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("got %d cookies, want 1", len(cookies))
		}
		cookie = cookies[0]
	} else if len(w.Result().Cookies()) != 0 {
		t.Fatal("valid cookie unexpectedly replaced")
	}
	return result.Result, cookie
}

func TestShortenRedirectAndUserIsolation(t *testing.T) {
	a := newApp(t)
	original := "https://example.com/some/long/path?q=one%20two&lang=ru#part"
	first, alice := shorten(t, a, original, nil)
	second, _ := shorten(t, a, "http://example.org/other", alice)
	third, bob := shorten(t, a, original, nil)
	if first == second || first == third || alice.Value == bob.Value {
		t.Fatal("URLs or users collided")
	}
	manager, _ := auth.New(app.DefaultSecret, false)
	if id, err := manager.Parse(alice.Value); err != nil || id == "" {
		t.Fatalf("cookie not signed correctly: %v", err)
	}
	w := request(a, http.MethodGet, first, "", nil)
	if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != original {
		t.Fatalf("redirect = %d, %q", w.Code, w.Header().Get("Location"))
	}
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		want   []app.UserURL
	}{
		{"alice", alice, []app.UserURL{{ShortURL: first, OriginalURL: original}, {ShortURL: second, OriginalURL: "http://example.org/other"}}},
		{"bob", bob, []app.UserURL{{ShortURL: third, OriginalURL: original}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(a, http.MethodGet, "/api/user/urls", "", tc.cookie)
			if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("list status = %d", w.Code)
			}
			var links []app.UserURL
			if err := json.Unmarshal(w.Body.Bytes(), &links); err != nil {
				t.Fatal(err)
			}
			if len(links) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", links, tc.want)
			}
			for i := range links {
				if links[i] != tc.want[i] {
					t.Fatalf("link = %+v, want %+v", links[i], tc.want[i])
				}
			}
		})
	}
}

func TestListCookieContract(t *testing.T) {
	a := newApp(t)
	_, owner := shorten(t, a, "https://example.com/private-list", nil)
	id, signature, _ := strings.Cut(owner.Value, ":")
	// Create a valid identity that has no stored links.
	empty := request(a, http.MethodGet, "/api/user/urls", "", nil).Result().Cookies()[0]
	cases := []struct {
		name      string
		cookie    *http.Cookie
		status    int
		newCookie bool
	}{
		{"absent", nil, http.StatusNoContent, true},
		{"valid empty user", empty, http.StatusNoContent, false},
		{"empty", &http.Cookie{Name: auth.CookieName, Value: ""}, http.StatusUnauthorized, false},
		{"no ID", &http.Cookie{Name: auth.CookieName, Value: ":" + signature}, http.StatusUnauthorized, false},
		{"no separator", &http.Cookie{Name: auth.CookieName, Value: "broken"}, http.StatusUnauthorized, false},
		{"no signature", &http.Cookie{Name: auth.CookieName, Value: id + ":"}, http.StatusUnauthorized, false},
		{"extra segment", &http.Cookie{Name: auth.CookieName, Value: owner.Value + ":extra"}, http.StatusUnauthorized, false},
		{"changed ID", &http.Cookie{Name: auth.CookieName, Value: "attacker:" + signature}, http.StatusNoContent, true},
		{"changed signature", &http.Cookie{Name: auth.CookieName, Value: id + ":" + strings.Repeat("0", 64)}, http.StatusNoContent, true},
		{"invalid hex", &http.Cookie{Name: auth.CookieName, Value: id + ":not-hex"}, http.StatusNoContent, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := request(a, http.MethodGet, "/api/user/urls", "", tc.cookie)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			cookies := w.Result().Cookies()
			if (len(cookies) == 1) != tc.newCookie {
				t.Fatalf("unexpected Set-Cookie: %v", cookies)
			}
			if tc.status == http.StatusNoContent && w.Body.Len() != 0 {
				t.Fatal("204 response has a body")
			}
			if tc.newCookie {
				m, _ := auth.New(app.DefaultSecret, false)
				newID, err := m.Parse(cookies[0].Value)
				if err != nil || newID == id || newID == "attacker" {
					t.Fatalf("invalid replacement identity: %q, %v", newID, err)
				}
			}
		})
	}
}

func TestShortenReplacesBadCookie(t *testing.T) {
	a := newApp(t)
	_, owner := shorten(t, a, "https://example.com/owner", nil)
	id, _, _ := strings.Cut(owner.Value, ":")
	for _, value := range []string{"", "broken", ":signature", id + ":" + strings.Repeat("0", 64)} {
		w := request(a, http.MethodPost, "/api/shorten", `{"url":"https://example.com/new"}`, &http.Cookie{Name: auth.CookieName, Value: value})
		if w.Code != http.StatusCreated || len(w.Result().Cookies()) != 1 {
			t.Fatalf("bad cookie %q: %d, %s", value, w.Code, w.Body.String())
		}
		list := request(a, http.MethodGet, "/api/user/urls", "", w.Result().Cookies()[0])
		var links []app.UserURL
		if err := json.Unmarshal(list.Body.Bytes(), &links); err != nil || len(links) != 1 || links[0].OriginalURL != "https://example.com/new" {
			t.Fatalf("replacement user list = %s, error=%v", list.Body.String(), err)
		}
	}
	list := request(a, http.MethodGet, "/api/user/urls", "", owner)
	var links []app.UserURL
	if err := json.Unmarshal(list.Body.Bytes(), &links); err != nil || len(links) != 1 || links[0].OriginalURL != "https://example.com/owner" {
		t.Fatal("tampering modified the original user's list")
	}
}

func TestInvalidShortenRequests(t *testing.T) {
	a := newApp(t)
	cases := []struct {
		name, body string
	}{
		{"empty body", ""},
		{"broken JSON", `{"url":`},
		{"missing URL", `{}`},
		{"empty URL", `{"url":""}`},
		{"null", `null`},
		{"array", `[]`},
		{"numeric URL", `{"url":123}`},
		{"null URL", `{"url":null}`},
		{"relative URL", `{"url":"/path"}`},
		{"no scheme", `{"url":"example.com"}`},
		{"unsupported scheme", `{"url":"javascript:alert(1)"}`},
		{"no hostname", `{"url":"https://:8080/path"}`},
		{"invalid port", `{"url":"https://example.com:99999"}`},
		{"invalid escape", `{"url":"https://example.com/%zz"}`},
		{"whitespace", `{"url":" https://example.com"}`},
		{"line break", `{"url":"https://example.com/\r\nInjected:yes"}`},
		{"extra field", `{"url":"https://example.com","extra":true}`},
		{"two JSON objects", `{"url":"https://example.com"} {}`},
		{"trailing garbage", `{"url":"https://example.com"}oops`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := request(a, http.MethodPost, "/api/shorten", tc.body, nil)
			if w.Code != http.StatusBadRequest || !json.Valid(w.Body.Bytes()) {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
		})
	}
	w := request(a, http.MethodPost, "/api/shorten", `{"url":"https://example.com/`+strings.Repeat("a", 1<<20)+`"}`, nil)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d", w.Code)
	}
	w = request(a, http.MethodPost, "/api/shorten", `{"url":"https://example.com"}`+strings.Repeat(" ", 1<<20), nil)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized trailing data status = %d", w.Code)
	}
}

func TestContentType(t *testing.T) {
	a := newApp(t)
	for _, tc := range []struct {
		value  string
		status int
	}{
		{"", http.StatusCreated},
		{"application/json", http.StatusCreated},
		{"application/json; charset=utf-8", http.StatusCreated},
		{"text/plain", http.StatusUnsupportedMediaType},
		{"application/json; bad", http.StatusUnsupportedMediaType},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/shorten", strings.NewReader(`{"url":"https://example.com"}`))
		r.Header.Set("Content-Type", tc.value)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("Content-Type %q: got %d, want %d", tc.value, w.Code, tc.status)
		}
	}
}

func TestRouting(t *testing.T) {
	a := newApp(t)
	for _, path := range []string{"/", "/missing", "/nested/path", "/api/user/urls/", "/api/shorten/"} {
		if w := request(a, http.MethodGet, path, "", nil); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d", path, w.Code)
		}
	}
	for _, tc := range []struct {
		path, method, allow string
	}{
		{"/api/shorten", http.MethodGet, http.MethodPost},
		{"/api/user/urls", http.MethodPost, http.MethodGet},
		{"/1", http.MethodDelete, http.MethodGet},
	} {
		w := request(a, tc.method, tc.path, "", nil)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != tc.allow {
			t.Errorf("%s %s = %d, Allow=%q", tc.method, tc.path, w.Code, w.Header().Get("Allow"))
		}
	}
}

func TestConfiguration(t *testing.T) {
	for _, base := range []string{"relative", "ftp://example.com", "https://example.com/path", "https://example.com?q=1", "https://example.com?", "https://example.com#", "https://example.com#fragment", "https://user:pass@example.com", "https://example.com:99999", "https://:80"} {
		if _, err := app.New(app.Config{BaseURL: base}); err == nil {
			t.Errorf("invalid base URL accepted: %s", base)
		}
	}
	a, err := app.New(app.Config{BaseURL: "https://short.example/", SecretKey: "custom-secret"})
	if err != nil {
		t.Fatal(err)
	}
	w := request(a, http.MethodPost, "/api/shorten", `{"url":"https://example.com"}`, nil)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "https://short.example/1") {
		t.Fatalf("custom base URL response = %d %s", w.Code, w.Body.String())
	}
	c := w.Result().Cookies()[0]
	m, _ := auth.New("custom-secret", true)
	if _, err := m.Parse(c.Value); err != nil || !c.Secure {
		t.Fatal("custom signing key or secure cookie not applied")
	}
}

func TestConcurrentHTTPRequests(t *testing.T) {
	a := newApp(t)
	const count = 100
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			original := fmt.Sprintf("https://example.com/%d", i)
			created := request(a, http.MethodPost, "/api/shorten", fmt.Sprintf(`{"url":%q}`, original), nil)
			var result struct {
				Result string `json:"result"`
			}
			if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || created.Code != http.StatusCreated || len(created.Result().Cookies()) != 1 {
				t.Errorf("concurrent create failed: %d %s", created.Code, created.Body.String())
				return
			}
			short, cookie := result.Result, created.Result().Cookies()[0]
			w := request(a, http.MethodGet, "/api/user/urls", "", cookie)
			var links []app.UserURL
			if err := json.Unmarshal(w.Body.Bytes(), &links); err != nil || len(links) != 1 || links[0].ShortURL != short || links[0].OriginalURL != original {
				t.Errorf("isolated list = %s, error=%v", w.Body.String(), err)
			}
			w = request(a, http.MethodGet, short, "", nil)
			if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != original {
				t.Errorf("concurrent redirect failed: %d", w.Code)
			}
		}(i)
	}
	wg.Wait()
}

func TestHTTPClientWithCookieJar(t *testing.T) {
	server := httptest.NewServer(newApp(t))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	res, err := client.Post(server.URL+"/api/shorten", "application/json", strings.NewReader(`{"url":"https://example.com/live"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d", res.StatusCode)
	}
	res, err = client.Get(server.URL + "/api/user/urls")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != http.StatusOK || !strings.Contains(string(data), "https://example.com/live") {
		t.Fatalf("cookie jar did not preserve identity: %d %s, %v", res.StatusCode, data, err)
	}
	parsed, _ := url.Parse(server.URL)
	if len(jar.Cookies(parsed)) != 1 {
		t.Fatal("user cookie missing from jar")
	}
}
