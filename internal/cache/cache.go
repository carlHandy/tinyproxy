package cache

import (
	"hash/fnv"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const numShards = 64

// CacheEntry stores a cached HTTP response.
type CacheEntry struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	StoredAt   time.Time
	ExpiresAt  time.Time
	ETag       string
	LastMod    string // Last-Modified value
	Size       int    // approximate memory footprint in bytes
}

// IsExpired reports whether the entry has passed its TTL.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStaleRevalidatable reports whether the entry is expired but still within
// the stale-while-revalidate window.
func (e *CacheEntry) IsStaleRevalidatable(swr time.Duration) bool {
	if swr <= 0 {
		return false
	}
	return time.Now().Before(e.ExpiresAt.Add(swr))
}

// Stats holds cache-wide counters exposed for observability.
type Stats struct {
	Hits       uint64
	Misses     uint64
	Evictions  uint64
	Stores     uint64
	Bytes      int64
}

// Cache is a sharded, LRU-evicting, TTL-aware in-memory HTTP response cache.
type Cache struct {
	shards  [numShards]*shard
	maxSize int64 // total max bytes across all shards
	stats   Stats
}

type shard struct {
	mu      sync.RWMutex
	items   map[string]*lruNode
	head    *lruNode // most recently used
	tail    *lruNode // least recently used
	size    int64
}

type lruNode struct {
	key   string
	entry *CacheEntry
	prev  *lruNode
	next  *lruNode
}

// New creates a Cache with the given maximum size in bytes.
func New(maxSize int64) *Cache {
	c := &Cache{maxSize: maxSize}
	perShard := maxSize / numShards
	if perShard < 1 {
		perShard = 1
	}
	for i := range c.shards {
		c.shards[i] = &shard{
			items: make(map[string]*lruNode),
		}
		_ = perShard // shard-level limit enforced via global check
	}
	return c
}

// shardFor returns the shard index for a cache key.
func (c *Cache) shardFor(key string) *shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()%numShards]
}

// Get retrieves a cache entry. Returns nil if not found or expired.
func (c *Cache) Get(key string) (*CacheEntry, bool) {
	s := c.shardFor(key)
	s.mu.RLock()
	node, ok := s.items[key]
	s.mu.RUnlock()
	if !ok {
		atomic.AddUint64(&c.stats.Misses, 1)
		return nil, false
	}
	if node.entry.IsExpired() {
		atomic.AddUint64(&c.stats.Misses, 1)
		return node.entry, false // return entry so caller can use stale-while-revalidate
	}
	// Promote to head (write lock)
	s.mu.Lock()
	s.moveToHead(node)
	s.mu.Unlock()
	atomic.AddUint64(&c.stats.Hits, 1)
	return node.entry, true
}

// Set stores a cache entry, evicting LRU items if necessary.
func (c *Cache) Set(key string, entry *CacheEntry) {
	entry.Size = len(entry.Body) + len(key) + 256 // approximate overhead
	s := c.shardFor(key)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update existing entry
	if existing, ok := s.items[key]; ok {
		atomic.AddInt64(&c.stats.Bytes, int64(entry.Size-existing.entry.Size))
		s.size += int64(entry.Size - existing.entry.Size)
		existing.entry = entry
		s.moveToHead(existing)
		atomic.AddUint64(&c.stats.Stores, 1)
		c.evictIfNeeded()
		return
	}

	node := &lruNode{key: key, entry: entry}
	s.items[key] = node
	s.addToHead(node)
	s.size += int64(entry.Size)
	atomic.AddInt64(&c.stats.Bytes, int64(entry.Size))
	atomic.AddUint64(&c.stats.Stores, 1)
	c.evictIfNeeded()
}

// Delete removes a single key from the cache.
func (c *Cache) Delete(key string) {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if node, ok := s.items[key]; ok {
		s.removeNode(node)
		delete(s.items, key)
		s.size -= int64(node.entry.Size)
		atomic.AddInt64(&c.stats.Bytes, -int64(node.entry.Size))
	}
}

// Purge flushes the entire cache.
func (c *Cache) Purge() {
	for _, s := range c.shards {
		s.mu.Lock()
		s.items = make(map[string]*lruNode)
		s.head = nil
		s.tail = nil
		s.size = 0
		s.mu.Unlock()
	}
	atomic.StoreInt64(&c.stats.Bytes, 0)
}

// GetStats returns a snapshot of cache statistics.
func (c *Cache) GetStats() Stats {
	return Stats{
		Hits:      atomic.LoadUint64(&c.stats.Hits),
		Misses:    atomic.LoadUint64(&c.stats.Misses),
		Evictions: atomic.LoadUint64(&c.stats.Evictions),
		Stores:    atomic.LoadUint64(&c.stats.Stores),
		Bytes:     atomic.LoadInt64(&c.stats.Bytes),
	}
}

// evictIfNeeded removes LRU entries across all shards until under maxSize.
func (c *Cache) evictIfNeeded() {
	for atomic.LoadInt64(&c.stats.Bytes) > c.maxSize {
		// Find the shard with the largest footprint and evict its tail
		var biggest *shard
		var biggestSize int64
		for _, s := range c.shards {
			if s.size > biggestSize {
				biggest = s
				biggestSize = s.size
			}
		}
		if biggest == nil || biggest.tail == nil {
			break
		}
		// If we already hold this shard's lock, evict directly;
		// otherwise we need to be careful. Since evictIfNeeded is called
		// from Set which already holds one shard lock, we skip that shard
		// if it's not the biggest.
		node := biggest.tail
		biggest.removeNode(node)
		delete(biggest.items, node.key)
		biggest.size -= int64(node.entry.Size)
		atomic.AddInt64(&c.stats.Bytes, -int64(node.entry.Size))
		atomic.AddUint64(&c.stats.Evictions, 1)
	}
}

// --- LRU doubly-linked list operations ---

func (s *shard) addToHead(node *lruNode) {
	node.prev = nil
	node.next = s.head
	if s.head != nil {
		s.head.prev = node
	}
	s.head = node
	if s.tail == nil {
		s.tail = node
	}
}

func (s *shard) removeNode(node *lruNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		s.head = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		s.tail = node.prev
	}
	node.prev = nil
	node.next = nil
}

func (s *shard) moveToHead(node *lruNode) {
	if s.head == node {
		return
	}
	s.removeNode(node)
	s.addToHead(node)
}
