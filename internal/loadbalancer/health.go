package loadbalancer

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// HealthChecker periodically probes backends and updates their alive status.
type HealthChecker struct {
	backends  []*Backend
	cfg       HealthCheckConfig
	client    *http.Client
	stopCh    chan struct{}
}

// NewHealthChecker creates a HealthChecker (call Start to begin probing).
func NewHealthChecker(backends []*Backend, cfg HealthCheckConfig) *HealthChecker {
	return &HealthChecker{
		backends: backends,
		cfg:      cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			// Don't follow redirects during health checks
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		stopCh: make(chan struct{}),
	}
}

// Start begins the periodic health checking loop.
func (hc *HealthChecker) Start() {
	go hc.loop()
	slog.Info("health checker started",
		"interval", hc.cfg.Interval,
		"path", hc.cfg.Path,
		"backends", len(hc.backends),
	)
}

// Stop terminates the health checking loop.
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
}

func (hc *HealthChecker) loop() {
	ticker := time.NewTicker(hc.cfg.Interval)
	defer ticker.Stop()

	// Run an initial check immediately
	hc.checkAll()

	for {
		select {
		case <-ticker.C:
			hc.checkAll()
		case <-hc.stopCh:
			return
		}
	}
}

func (hc *HealthChecker) checkAll() {
	for _, b := range hc.backends {
		go hc.check(b)
	}
}

func (hc *HealthChecker) check(b *Backend) {
	url := fmt.Sprintf("%s%s", b.URL, hc.cfg.Path)
	resp, err := hc.client.Get(url)
	if err != nil {
		hc.recordFail(b, err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		hc.recordPass(b)
	} else {
		hc.recordFail(b, fmt.Errorf("status %d", resp.StatusCode))
	}
}

func (hc *HealthChecker) recordPass(b *Backend) {
	b.consecutiveFails.Store(0)
	passes := b.consecutivePasses.Add(1)

	if !b.IsAlive() && int(passes) >= hc.cfg.PassThreshold {
		b.SetAlive(true)
		slog.Info("backend recovered", "url", b.URL, "passes", passes)
	}
}

func (hc *HealthChecker) recordFail(b *Backend, err error) {
	b.consecutivePasses.Store(0)
	fails := b.consecutiveFails.Add(1)

	if b.IsAlive() && int(fails) >= hc.cfg.FailThreshold {
		b.SetAlive(false)
		slog.Warn("backend marked down",
			"url", b.URL,
			"consecutive_fails", fails,
			"error", err,
		)
	}
}

// Stats returns a snapshot of backend health for observability.
type HealthStats struct {
	URL              string
	Alive            bool
	ActiveConns      int64
	ConsecutiveFails int32
}

func (hc *HealthChecker) Stats() []HealthStats {
	stats := make([]HealthStats, len(hc.backends))
	for i, b := range hc.backends {
		stats[i] = HealthStats{
			URL:              b.URL,
			Alive:            b.IsAlive(),
			ActiveConns:      b.ActiveConns(),
			ConsecutiveFails: b.consecutiveFails.Load(),
		}
	}
	return stats
}
