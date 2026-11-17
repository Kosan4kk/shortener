package storage

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestMemoryOwnershipAndSnapshots(t *testing.T) {
	m := NewMemory()
	first, err := m.Add("alice", "https://example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := m.Add("alice", "https://example.com/b")
	third, _ := m.Add("bob", first.OriginalURL)
	if first.ID == second.ID || first.ID == third.ID || second.ID == third.ID {
		t.Fatal("IDs collided")
	}
	if original, ok := m.Resolve(first.ID); !ok || original != first.OriginalURL {
		t.Fatalf("Resolve = %q, %v", original, ok)
	}
	if _, ok := m.Resolve("missing"); ok {
		t.Fatal("unknown ID found")
	}
	links := m.List("alice")
	if len(links) != 2 || links[0] != first || links[1] != second {
		t.Fatalf("unexpected Alice list: %+v", links)
	}
	links[0].OriginalURL = "https://attacker.test"
	if m.List("alice")[0] != first {
		t.Fatal("caller mutated storage through returned slice")
	}
	if bob := m.List("bob"); len(bob) != 1 || bob[0] != third {
		t.Fatalf("unexpected Bob list: %+v", bob)
	}
	if len(m.List("unknown")) != 0 {
		t.Fatal("unknown user has links")
	}
}

func TestMemoryConcurrentAccess(t *testing.T) {
	m := NewMemory()
	const workers, perUser = 20, 50
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", i)
			for j := 0; j < perUser; j++ {
				original := fmt.Sprintf("https://example.com/%d/%d", i, j)
				link, err := m.Add(user, original)
				if err != nil {
					t.Error(err)
					return
				}
				if got, ok := m.Resolve(link.ID); !ok || got != original {
					t.Errorf("URL lost: %q", got)
				}
				_ = m.List(user)
			}
		}(i)
	}
	wg.Wait()
	seen := make(map[string]bool)
	for i := 0; i < workers; i++ {
		links := m.List(fmt.Sprintf("user-%d", i))
		if len(links) != perUser {
			t.Fatalf("user %d has %d URLs, want %d", i, len(links), perUser)
		}
		for _, link := range links {
			if seen[link.ID] {
				t.Fatalf("duplicate ID %q", link.ID)
			}
			seen[link.ID] = true
		}
	}
}

func TestMemoryCounterExhaustion(t *testing.T) {
	m := NewMemory()
	m.nextID = ^uint64(0)
	if _, err := m.Add("alice", "https://example.com"); !errors.Is(err, ErrIDExhausted) {
		t.Fatalf("overflow error = %v", err)
	}
	if len(m.List("alice")) != 0 || len(m.urls) != 0 {
		t.Fatal("failed allocation modified storage")
	}
}
