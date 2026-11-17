// Package storage implements process-local URL storage without a database.
package storage

import (
	"errors"
	"strconv"
	"sync"
)

var ErrIDExhausted = errors.New("short URL ID space exhausted")

// Link stores an ID rather than a public URL so HTTP configuration stays in app.
type Link struct {
	ID          string
	OriginalURL string
}

// Memory must be constructed with NewMemory and must not be copied after use.
type Memory struct {
	mu     sync.RWMutex
	nextID uint64
	urls   map[string]string
	byUser map[string][]Link
}

func NewMemory() *Memory {
	return &Memory{urls: make(map[string]string), byUser: make(map[string][]Link)}
}

// Add allocates a collision-free base-36 ID and updates both indexes atomically.
// Repeated URLs intentionally get separate IDs, including for different users.
func (m *Memory) Add(userID, originalURL string) (Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nextID == ^uint64(0) {
		return Link{}, ErrIDExhausted
	}
	m.nextID++
	link := Link{ID: strconv.FormatUint(m.nextID, 36), OriginalURL: originalURL}
	m.urls[link.ID] = originalURL
	m.byUser[userID] = append(m.byUser[userID], link)
	return link, nil
}

func (m *Memory) Resolve(id string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	original, ok := m.urls[id]
	return original, ok
}

// List returns a snapshot in creation order; callers cannot mutate the store.
func (m *Memory) List(userID string) []Link {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Link(nil), m.byUser[userID]...)
}
