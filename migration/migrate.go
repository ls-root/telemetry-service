// +build ignore

// Migration script to import data from the old API to PocketBase
// Run with: go run migrate.go
//
// Environment variables:
//   MIGRATION_SOURCE_URL  - Base URL of source API (default: https://api.htl-braunau.at/data)
//   POCKETBASE_URL        - PocketBase URL (default: http://localhost:8090)
//   POCKETBASE_COLLECTION - Target collection (default: telemetry)
//   PB_IDENTITY           - Auth username
//   PB_PASSWORD           - Auth password
//   REPO_SOURCE           - Value for repo_source field (e.g., "community-scripts" or "Proxmox VE")
//   DATE_UNTIL            - Only import records created before this date (format: YYYY-MM-DD)
//   START_PAGE            - Resume from this page (default: 1)
//   BATCH_SIZE            - Records per page (default: 500)
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSourceAPI = "https://api.htl-braunau.at/data"
	defaultPBURL     = "http://localhost:8090"
	defaultBatchSize = 500
	workerCount      = 5 // Parallel workers for importing
)

var (
	sourceAPI      string
	summaryAPI     string
	authToken      string
	repoSource     string
	dateUntil      time.Time
	dateFrom       time.Time
	hasDateUntil   bool
	hasDateFrom    bool
)

// OldDataModel represents the data structure from the old API
type OldDataModel struct {
	ID         string `json:"id"`
	CtType     int    `json:"ct_type"`
	DiskSize   int    `json:"disk_size"`
	CoreCount  int    `json:"core_count"`
	RamSize    int    `json:"ram_size"`
	OsType     string `json:"os_type"`
	OsVersion  string `json:"os_version"`
	DisableIP6 string `json:"disableip6"`
	NsApp      string `json:"nsapp"`
	Method     string `json:"method"`
	CreatedAt  string `json:"created_at"`
	PveVersion string `json:"pve_version"`
	Status     string `json:"status"`
	RandomID   string `json:"random_id"`
	Type       string `json:"type"`
	Error      string `json:"error"`
}

// PBRecord represents the PocketBase record format
type PBRecord struct {
	CtType     int    `json:"ct_type"`
	DiskSize   int    `json:"disk_size"`
	CoreCount  int    `json:"core_count"`
	RamSize    int    `json:"ram_size"`
	OsType     string `json:"os_type"`
	OsVersion  string `json:"os_version"`
	DisableIP6 string `json:"disableip6"`
	NsApp      string `json:"nsapp"`
	Method     string `json:"method"`
	PveVersion string `json:"pve_version"`
	Status     string `json:"status"`
	RandomID   string `json:"random_id"`
	Type       string `json:"type"`
	Error      string `json:"error"`
	RepoSource string `json:"repo_source,omitempty"`
	OldCreated string `json:"old_created,omitempty"`
}

type Summary struct {
	TotalEntries int `json:"total_entries"`
}

type ImportJob struct {
	Record OldDataModel
	Index  int
}

type ImportResult struct {
	Success bool
	Skipped bool
	Error   error
}

func main() {
	// Setup source URLs
	baseURL := os.Getenv("MIGRATION_SOURCE_URL")
	if baseURL == "" {
		baseURL = defaultSourceAPI
	}
	sourceAPI = baseURL + "/paginated"
	summaryAPI = baseURL + "/summary"

	// Repo source (to distinguish data origins)
	repoSource = os.Getenv("REPO_SOURCE")

	// Date filters
	if dateStr := os.Getenv("DATE_UNTIL"); dateStr != "" {
		parsed, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			fmt.Printf("[ERROR] Invalid DATE_UNTIL format (use YYYY-MM-DD): %v\n", err)
			os.Exit(1)
		}
		dateUntil = parsed.Add(24*time.Hour - time.Second) // End of day
		hasDateUntil = true
	}

	if dateStr := os.Getenv("DATE_FROM"); dateStr != "" {
		parsed, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			fmt.Printf("[ERROR] Invalid DATE_FROM format (use YYYY-MM-DD): %v\n", err)
			os.Exit(1)
		}
		dateFrom = parsed // Start of day
		hasDateFrom = true
	}

	// Batch size
	batchSize := defaultBatchSize
	if bs := os.Getenv("BATCH_SIZE"); bs != "" {
		if n, err := strconv.Atoi(bs); err == nil && n > 0 {
			batchSize = n
		}
	}

	// Start page (for resuming)
	startPage := 1
	if sp := os.Getenv("START_PAGE"); sp != "" {
		if n, err := strconv.Atoi(sp); err == nil && n > 0 {
			startPage = n
		}
	}

	// PocketBase URL
	pbURL := os.Getenv("POCKETBASE_URL")
	if pbURL == "" {
		pbURL = os.Getenv("PB_URL")
	}
	if pbURL == "" {
		pbURL = defaultPBURL
	}

	// Collection
	pbCollection := os.Getenv("POCKETBASE_COLLECTION")
	if pbCollection == "" {
		pbCollection = os.Getenv("PB_TARGET_COLLECTION")
	}
	if pbCollection == "" {
		pbCollection = "telemetry"
	}

	// Auth collection
	authCollection := os.Getenv("PB_AUTH_COLLECTION")
	if authCollection == "" {
		authCollection = "telemetry_service_user"
	}

	// Credentials
	pbIdentity := os.Getenv("PB_IDENTITY")
	pbPassword := os.Getenv("PB_PASSWORD")

	fmt.Println("=========================================================")
	fmt.Println("        Data Migration to PocketBase")
	fmt.Println("=========================================================")
	fmt.Printf("Source API:       %s\n", baseURL)
	fmt.Printf("PocketBase URL:   %s\n", pbURL)
	fmt.Printf("Collection:       %s\n", pbCollection)
	fmt.Printf("Batch Size:       %d\n", batchSize)
	fmt.Printf("Workers:          %d\n", workerCount)
	if repoSource != "" {
		fmt.Printf("Repo Source:      %s\n", repoSource)
	}
	if hasDateFrom {
		fmt.Printf("Date From:        >= %s\n", dateFrom.Format("2006-01-02"))
	}
	if hasDateUntil {
		fmt.Printf("Date Until:       <= %s\n", dateUntil.Format("2006-01-02"))
	}
	if startPage > 1 {
		fmt.Printf("Starting Page:    %d\n", startPage)
	}
	fmt.Println("---------------------------------------------------------")

	// Authenticate with PocketBase
	if pbIdentity != "" && pbPassword != "" {
		fmt.Println("[AUTH] Authenticating with PocketBase...")
		err := authenticate(pbURL, authCollection, pbIdentity, pbPassword)
		if err != nil {
			fmt.Printf("[ERROR] Authentication failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[OK] Authentication successful")
	} else {
		fmt.Println("[WARN] No credentials provided, trying without auth...")
	}
	fmt.Println("---------------------------------------------------------")

	// Get total count
	summary, err := getSummary()
	if err != nil {
		fmt.Printf("[ERROR] Failed to get summary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[INFO] Total entries in source: %d\n", summary.TotalEntries)
	fmt.Println("---------------------------------------------------------")

	// Calculate pages
	totalPages := (summary.TotalEntries + batchSize - 1) / batchSize

	fmt.Printf("Starting migration (%d pages to process)...\n", totalPages)
	fmt.Println()

	var totalMigrated, totalFailed, totalSkipped, totalFiltered int64
	startTime := time.Now()

	// Progress tracking
	processedRecords := int64(0)

	for page := startPage; page <= totalPages; page++ {
		pageStart := time.Now()

		if page == startPage {
			fmt.Printf("Fetching page %d...\n", page)
		}

		data, err := fetchPage(page, batchSize)
		if err != nil {
			fmt.Printf("\n[ERROR] Failed to fetch page %d: %v\n", page, err)
			atomic.AddInt64(&totalFailed, int64(batchSize))
			continue
		}

		// Filter by date if needed
		var filteredData []OldDataModel
		var lastTimestamp string

		for _, record := range data {
			recordDate, err := parseTimestamp(record.CreatedAt)
			if err != nil {
				// Skip records with unparseable dates
				atomic.AddInt64(&totalFiltered, 1)
				continue
			}

			// Check DATE_FROM (skip if before)
			if hasDateFrom && recordDate.Before(dateFrom) {
				atomic.AddInt64(&totalFiltered, 1)
				continue
			}

			// Check DATE_UNTIL (skip if after)
			if hasDateUntil && recordDate.After(dateUntil) {
				atomic.AddInt64(&totalFiltered, 1)
				continue
			}

			filteredData = append(filteredData, record)
			lastTimestamp = record.CreatedAt
		}

		if len(filteredData) == 0 {
			atomic.AddInt64(&processedRecords, int64(len(data)))
			continue
		}

		// Worker pool for importing
		jobs := make(chan ImportJob, len(filteredData))
		results := make(chan ImportResult, len(filteredData))
		var wg sync.WaitGroup

		// Start workers
		for w := 0; w < workerCount; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					result := importRecordWithRetry(pbURL, pbCollection, job.Record, 3)
					results <- result
				}
			}()
		}

		// Send jobs
		for i, record := range filteredData {
			jobs <- ImportJob{Record: record, Index: i}
		}
		close(jobs)

		// Wait for workers to finish
		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect results
		pageMigrated, pageSkipped, pageFailed := 0, 0, 0
		for result := range results {
			if result.Skipped {
				pageSkipped++
			} else if result.Success {
				pageMigrated++
			} else {
				pageFailed++
			}
		}

		atomic.AddInt64(&totalMigrated, int64(pageMigrated))
		atomic.AddInt64(&totalSkipped, int64(pageSkipped))
		atomic.AddInt64(&totalFailed, int64(pageFailed))
		atomic.AddInt64(&processedRecords, int64(len(data)))

		// Progress display (first 5 pages, then every 10 pages)
		if page <= 5 || page%10 == 0 || page == totalPages {
			elapsed := time.Since(startTime)
			processed := atomic.LoadInt64(&processedRecords)
			rate := float64(processed) / elapsed.Seconds()
			remaining := float64(summary.TotalEntries-int(processed)) / rate
			eta := time.Duration(remaining) * time.Second

			// Format last timestamp for display
			lastDate := ""
			if lastTimestamp != "" {
				if t, err := parseTimestamp(lastTimestamp); err == nil {
					lastDate = t.Format("2006-01-02")
				}
			}

			fmt.Printf("[Page %d/%d] Migrated: %d | Skipped: %d | Failed: %d | Filtered: %d | %.0f rec/s | Last: %s | ETA: %s\n",
				page, totalPages,
				atomic.LoadInt64(&totalMigrated),
				atomic.LoadInt64(&totalSkipped),
				atomic.LoadInt64(&totalFailed),
				atomic.LoadInt64(&totalFiltered),
				rate,
				lastDate,
				formatDuration(eta))
		}

		// Adaptive delay based on page processing time
		pageTime := time.Since(pageStart)
		if pageTime < 500*time.Millisecond {
			time.Sleep(100 * time.Millisecond)
		}
	}

	fmt.Println()
	fmt.Println("=========================================================")
	fmt.Println("        Migration Complete")
	fmt.Println("=========================================================")
	fmt.Printf("Successfully migrated: %d\n", atomic.LoadInt64(&totalMigrated))
	fmt.Printf("Skipped (duplicates):  %d\n", atomic.LoadInt64(&totalSkipped))
	fmt.Printf("Filtered (date):       %d\n", atomic.LoadInt64(&totalFiltered))
	fmt.Printf("Failed:                %d\n", atomic.LoadInt64(&totalFailed))
	fmt.Printf("Duration:              %s\n", formatDuration(time.Since(startTime)))
	fmt.Println("=========================================================")

	if atomic.LoadInt64(&totalMigrated) > 0 {
		fmt.Println()
		fmt.Println("Next steps for timestamp migration:")
		fmt.Printf("   1. SSH into your PocketBase server\n")
		fmt.Printf("   2. Run: sqlite3 /app/pb_data/data.db \".tables\"\n")
		fmt.Printf("   3. Find your collection table name\n")
		fmt.Printf("   4. Run: sqlite3 /app/pb_data/data.db \"UPDATE <table_name> SET created = old_created, updated = old_created WHERE old_created IS NOT NULL AND old_created != ''\"\n")
		fmt.Printf("   5. Remove the old_created field from the collection in PocketBase Admin UI\n")
	}
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		return "calculating..."
	}
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func parseTimestamp(ts string) (time.Time, error) {
	if ts == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}

	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05.000 UTC",
		"2006-01-02T15:04:05.000+00:00",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("cannot parse: %s", ts)
}

func convertTimestamp(ts string) string {
	if ts == "" {
		return ""
	}

	t, err := parseTimestamp(ts)
	if err != nil {
		return ""
	}

	return t.UTC().Format("2006-01-02 15:04:05.000Z")
}

func getSummary() (*Summary, error) {
	resp, err := http.Get(summaryAPI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var summary Summary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return nil, err
	}

	return &summary, nil
}

func authenticate(pbURL, authCollection, identity, password string) error {
	body := map[string]string{
		"identity": identity,
		"password": password,
	}
	jsonData, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/api/collections/%s/auth-with-password", pbURL, authCollection)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if result.Token == "" {
		return fmt.Errorf("no token in response")
	}

	authToken = result.Token
	return nil
}

func fetchPage(page, limit int) ([]OldDataModel, error) {
	url := fmt.Sprintf("%s?page=%d&limit=%d", sourceAPI, page, limit)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var data []OldDataModel
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return data, nil
}

func importRecordWithRetry(pbURL, collection string, old OldDataModel, maxRetries int) ImportResult {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		err := importRecord(pbURL, collection, old)
		if err == nil {
			return ImportResult{Success: true}
		}
		if isUniqueViolation(err) {
			return ImportResult{Skipped: true}
		}
		lastErr = err
		time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
	}
	return ImportResult{Error: lastErr}
}

func importRecord(pbURL, collection string, old OldDataModel) error {
	// Map status: "done" -> "success"
	status := old.Status
	switch status {
	case "done":
		status = "success"
	case "installing", "failed", "unknown", "success":
		// keep as-is
	default:
		status = "unknown"
	}

	// Map ct_type: 1=unprivileged (0), 2=privileged (1)
	// PocketBase schema: 0 = unprivileged, 1 = privileged
	ctType := 0 // default: unprivileged
	if old.CtType == 2 {
		ctType = 1 // privileged
	}

	// Ensure type is set
	recordType := old.Type
	if recordType == "" {
		recordType = "lxc"
	}

	// Ensure nsapp is set (required field)
	nsapp := old.NsApp
	if nsapp == "" {
		nsapp = "unknown"
	}

	record := PBRecord{
		CtType:     ctType,
		DiskSize:   old.DiskSize,
		CoreCount:  old.CoreCount,
		RamSize:    old.RamSize,
		OsType:     old.OsType,
		OsVersion:  old.OsVersion,
		DisableIP6: old.DisableIP6,
		NsApp:      nsapp,
		Method:     old.Method,
		PveVersion: old.PveVersion,
		Status:     status,
		RandomID:   old.RandomID,
		Type:       recordType,
		Error:      old.Error,
		RepoSource: repoSource,
		OldCreated: convertTimestamp(old.CreatedAt),
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/collections/%s/records", pbURL, collection)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "UNIQUE constraint failed") ||
		strings.Contains(errStr, "duplicate") ||
		strings.Contains(errStr, "already exists") ||
		strings.Contains(errStr, "validation_not_unique")
}
