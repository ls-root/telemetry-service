package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

// CleanupConfig holds configuration for the cleanup job
type CleanupConfig struct {
	Enabled         bool
	CheckInterval   time.Duration // How often to run cleanup
	StuckAfterHours int           // Consider "installing" as stuck after X hours
}

// Cleaner handles cleanup of stuck installations
type Cleaner struct {
	cfg CleanupConfig
	pb  *PBClient
}

// NewCleaner creates a new cleaner instance
func NewCleaner(cfg CleanupConfig, pb *PBClient) *Cleaner {
	return &Cleaner{
		cfg: cfg,
		pb:  pb,
	}
}

// Start begins the cleanup loop
func (c *Cleaner) Start() {
	if !c.cfg.Enabled {
		log.Println("INFO: cleanup job disabled")
		return
	}

	go c.cleanupLoop()
	log.Printf("INFO: cleanup job started (interval: %v, stuck after: %d hours)", c.cfg.CheckInterval, c.cfg.StuckAfterHours)
}

func (c *Cleaner) cleanupLoop() {
	// Run immediately on start
	c.runCleanup()

	ticker := time.NewTicker(c.cfg.CheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.runCleanup()
	}
}

// runCleanup finds and updates stuck installations
func (c *Cleaner) runCleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Find stuck records
	stuckRecords, err := c.findStuckInstallations(ctx)
	if err != nil {
		log.Printf("WARN: cleanup - failed to find stuck installations: %v", err)
		return
	}

	if len(stuckRecords) == 0 {
		log.Printf("INFO: cleanup - no stuck installations found")
		return
	}

	log.Printf("INFO: cleanup - found %d stuck installations", len(stuckRecords))

	// Update each record
	updated := 0
	for _, record := range stuckRecords {
		if err := c.markAsUnknown(ctx, record.ID); err != nil {
			log.Printf("WARN: cleanup - failed to update record %s: %v", record.ID, err)
			continue
		}
		updated++
	}

	log.Printf("INFO: cleanup - updated %d stuck installations to 'unknown'", updated)
}

// StuckRecord represents a minimal record for cleanup
type StuckRecord struct {
	ID      string `json:"id"`
	NSAPP   string `json:"nsapp"`
	Created string `json:"created"`
}

// findStuckInstallations finds records that are stuck in "installing" status
func (c *Cleaner) findStuckInstallations(ctx context.Context) ([]StuckRecord, error) {
	if err := c.pb.ensureAuth(ctx); err != nil {
		return nil, err
	}

	// Calculate cutoff time
	cutoff := time.Now().Add(-time.Duration(c.cfg.StuckAfterHours) * time.Hour)
	cutoffStr := cutoff.Format("2006-01-02 15:04:05")

	// Build filter: status='installing' AND created < cutoff
	filter := url.QueryEscape(fmt.Sprintf("status='installing' && created<'%s'", cutoffStr))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/api/collections/%s/records?filter=%s&perPage=100",
			c.pb.baseURL, c.pb.targetColl, filter),
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.pb.token)

	resp, err := c.pb.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Items []StuckRecord `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Items, nil
}

// markAsUnknown updates a record's status to "unknown"
func (c *Cleaner) markAsUnknown(ctx context.Context, recordID string) error {
	update := TelemetryStatusUpdate{
		Status: "unknown",
		Error:  "Installation timed out - no completion status received",
	}
	return c.pb.UpdateTelemetryStatus(ctx, recordID, update)
}

// RunNow triggers an immediate cleanup run (for testing/manual trigger)
func (c *Cleaner) RunNow() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stuckRecords, err := c.findStuckInstallations(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to find stuck installations: %w", err)
	}

	updated := 0
	for _, record := range stuckRecords {
		if err := c.markAsUnknown(ctx, record.ID); err != nil {
			log.Printf("WARN: cleanup - failed to update record %s: %v", record.ID, err)
			continue
		}
		updated++
	}

	return updated, nil
}

// GetStuckCount returns the current number of stuck installations
func (c *Cleaner) GetStuckCount(ctx context.Context) (int, error) {
	records, err := c.findStuckInstallations(ctx)
	if err != nil {
		return 0, err
	}
	return len(records), nil
}
