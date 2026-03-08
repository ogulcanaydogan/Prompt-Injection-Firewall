package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

const (
	defaultReplayStoragePath   = "data/replay/events.jsonl"
	defaultReplayMaxFileSizeMB = 50
	defaultReplayMaxFiles      = 5
	defaultReplayMaxPromptChar = 512
)

var replayIDCounter uint64

var (
	replayRedactPattern = regexp.MustCompile(`(?i)(sk-[a-z0-9]{8,}|bearer\s+[a-z0-9\-_=\.]+|api[_-]?key\s*[:=]\s*[^\s,;]+)`)
)

// ReplayEventType identifies persisted forensics event categories.
type ReplayEventType string

const (
	ReplayEventTypeBlock     ReplayEventType = "block"
	ReplayEventTypeRateLimit ReplayEventType = "rate_limit"
	ReplayEventTypeScanError ReplayEventType = "scan_error"
	ReplayEventTypeFlag      ReplayEventType = "flag"
)

// ReplayRequestMeta stores request context persisted with replay events.
type ReplayRequestMeta struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Target    string `json:"target"`
	ClientKey string `json:"client_key"`
}

// ReplayPrompt stores captured prompt content used for later rescans.
type ReplayPrompt struct {
	Role      string `json:"role"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
	Redacted  bool   `json:"redacted"`
}

// ReplayEventRecord is a persisted forensics entry in JSONL.
type ReplayEventRecord struct {
	ReplayID    string             `json:"replay_id"`
	Timestamp   time.Time          `json:"timestamp"`
	Tenant      string             `json:"tenant"`
	EventType   ReplayEventType    `json:"event_type"`
	Decision    string             `json:"decision"`
	Score       float64            `json:"score"`
	Threshold   float64            `json:"threshold"`
	Findings    []detector.Finding `json:"findings"`
	RequestMeta ReplayRequestMeta  `json:"request_meta"`
	PayloadHash string             `json:"payload_hash"`
	Prompts     []ReplayPrompt     `json:"prompts,omitempty"`
}

// ReplayCaptureInput is the runtime payload passed by middleware.
type ReplayCaptureInput struct {
	Tenant      string
	EventType   ReplayEventType
	Decision    string
	Score       float64
	Threshold   float64
	Findings    []detector.Finding
	RequestMeta ReplayRequestMeta
	Body        []byte
	Inputs      []detector.ScanInput
}

// ReplayListFilter controls replay list query behavior.
type ReplayListFilter struct {
	Tenant    string
	EventType ReplayEventType
	Limit     int
}

// ReplayRescanResult contains detector re-evaluation output.
type ReplayRescanResult struct {
	ReplayID       string             `json:"replay_id"`
	Timestamp      time.Time          `json:"timestamp"`
	ScannedAt      time.Time          `json:"scanned_at"`
	Threshold      float64            `json:"threshold"`
	Score          float64            `json:"score"`
	FindingsCount  int                `json:"findings_count"`
	Findings       []detector.Finding `json:"findings"`
	Clean          bool               `json:"clean"`
	Decision       string             `json:"decision"`
	RescanPossible bool               `json:"rescan_possible"`
	Reason         string             `json:"reason,omitempty"`
}

// ReplayStore is used by middleware and dashboard for replay persistence and forensics.
type ReplayStore interface {
	Enabled() bool
	Record(input ReplayCaptureInput) error
	List(filter ReplayListFilter) ([]ReplayEventRecord, error)
	Get(id string) (*ReplayEventRecord, error)
	Rescan(ctx context.Context, id string, d detector.Detector) (*ReplayRescanResult, error)
}

type noopReplayStore struct{}

// NewNoopReplayStore returns a disabled replay store.
func NewNoopReplayStore() ReplayStore {
	return &noopReplayStore{}
}

func (s *noopReplayStore) Enabled() bool {
	return false
}

func (s *noopReplayStore) Record(input ReplayCaptureInput) error {
	return nil
}

func (s *noopReplayStore) List(filter ReplayListFilter) ([]ReplayEventRecord, error) {
	return []ReplayEventRecord{}, nil
}

func (s *noopReplayStore) Get(id string) (*ReplayEventRecord, error) {
	return nil, os.ErrNotExist
}

func (s *noopReplayStore) Rescan(ctx context.Context, id string, d detector.Detector) (*ReplayRescanResult, error) {
	return nil, os.ErrNotExist
}

// LocalReplayStore persists replay events to a rotating local JSONL file set.
type LocalReplayStore struct {
	mu               sync.Mutex
	logger           *slog.Logger
	storagePath      string
	maxFileSizeBytes int64
	maxFiles         int
	redactPrompt     bool
	maxPromptChars   int
}

// NewLocalReplayStore creates a local replay store from runtime options.
func NewLocalReplayStore(opts ReplayOptions, logger *slog.Logger) (ReplayStore, error) {
	if !opts.Enabled {
		return NewNoopReplayStore(), nil
	}

	storagePath := strings.TrimSpace(opts.StoragePath)
	if storagePath == "" {
		storagePath = defaultReplayStoragePath
	}
	maxFileSizeMB := opts.MaxFileSizeMB
	if maxFileSizeMB <= 0 {
		maxFileSizeMB = defaultReplayMaxFileSizeMB
	}
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultReplayMaxFiles
	}
	maxPromptChars := opts.MaxPromptChars
	if maxPromptChars <= 0 {
		maxPromptChars = defaultReplayMaxPromptChar
	}

	s := &LocalReplayStore{
		logger:           ensureLogger(logger),
		storagePath:      storagePath,
		maxFileSizeBytes: int64(maxFileSizeMB) * 1024 * 1024,
		maxFiles:         maxFiles,
		redactPrompt:     opts.RedactPromptContent,
		maxPromptChars:   maxPromptChars,
	}
	if err := os.MkdirAll(filepath.Dir(storagePath), 0755); err != nil {
		return nil, fmt.Errorf("creating replay storage directory: %w", err)
	}
	return s, nil
}

func (s *LocalReplayStore) Enabled() bool {
	return s != nil
}

func (s *LocalReplayStore) Record(input ReplayCaptureInput) error {
	if s == nil {
		return nil
	}

	event := ReplayEventRecord{
		ReplayID:    nextReplayID(),
		Timestamp:   time.Now().UTC(),
		Tenant:      fallbackString(strings.TrimSpace(input.Tenant), "default"),
		EventType:   input.EventType,
		Decision:    strings.TrimSpace(input.Decision),
		Score:       input.Score,
		Threshold:   input.Threshold,
		Findings:    cloneReplayFindings(input.Findings),
		RequestMeta: input.RequestMeta,
		PayloadHash: payloadHash(input.Body),
		Prompts:     s.capturePrompts(input.Inputs),
	}
	if event.Decision == "" {
		event.Decision = "unknown"
	}

	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.rotateIfNeededLocked(int64(len(line))); err != nil {
		return err
	}
	file, err := os.OpenFile(s.storagePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(line); err != nil {
		return err
	}
	return file.Sync()
}

func (s *LocalReplayStore) List(filter ReplayListFilter) ([]ReplayEventRecord, error) {
	events, err := s.readAllEvents()
	if err != nil {
		return nil, err
	}

	filtered := make([]ReplayEventRecord, 0, len(events))
	tenant := strings.TrimSpace(filter.Tenant)
	eventType := strings.TrimSpace(string(filter.EventType))
	for _, event := range events {
		if tenant != "" && event.Tenant != tenant {
			continue
		}
		if eventType != "" && string(event.EventType) != eventType {
			continue
		}
		filtered = append(filtered, event)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	if filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}

	return filtered, nil
}

func (s *LocalReplayStore) Get(id string) (*ReplayEventRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("replay id is required")
	}
	events, err := s.readAllEvents()
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if event.ReplayID == id {
			eventCopy := event
			return &eventCopy, nil
		}
	}
	return nil, os.ErrNotExist
}

func (s *LocalReplayStore) Rescan(ctx context.Context, id string, d detector.Detector) (*ReplayRescanResult, error) {
	if d == nil {
		return nil, fmt.Errorf("detector is required")
	}
	record, err := s.Get(id)
	if err != nil {
		return nil, err
	}

	inputs := make([]detector.ScanInput, 0, len(record.Prompts))
	for _, prompt := range record.Prompts {
		text := strings.TrimSpace(prompt.Text)
		if text == "" {
			continue
		}
		inputs = append(inputs, detector.ScanInput{Role: prompt.Role, Text: text})
	}
	if len(inputs) == 0 {
		return &ReplayRescanResult{
			ReplayID:       record.ReplayID,
			Timestamp:      record.Timestamp,
			ScannedAt:      time.Now().UTC(),
			Threshold:      record.Threshold,
			RescanPossible: false,
			Reason:         "no_prompt_content_available",
		}, nil
	}

	maxScore := 0.0
	allFindings := make([]detector.Finding, 0)
	for _, input := range inputs {
		result, err := d.Scan(ctx, input)
		if err != nil {
			return nil, err
		}
		if result.Score > maxScore {
			maxScore = result.Score
		}
		allFindings = append(allFindings, result.Findings...)
	}

	threshold := record.Threshold
	if threshold <= 0 {
		threshold = 0.5
	}
	clean := len(allFindings) == 0 || maxScore < threshold
	decision := "allow"
	if !clean {
		decision = "detect"
	}

	return &ReplayRescanResult{
		ReplayID:       record.ReplayID,
		Timestamp:      record.Timestamp,
		ScannedAt:      time.Now().UTC(),
		Threshold:      threshold,
		Score:          maxScore,
		FindingsCount:  len(allFindings),
		Findings:       cloneReplayFindings(allFindings),
		Clean:          clean,
		Decision:       decision,
		RescanPossible: true,
	}, nil
}

func (s *LocalReplayStore) capturePrompts(inputs []detector.ScanInput) []ReplayPrompt {
	if len(inputs) == 0 {
		return nil
	}
	prompts := make([]ReplayPrompt, 0, len(inputs))
	for _, input := range inputs {
		text := input.Text
		if text == "" {
			continue
		}
		prompt := ReplayPrompt{Role: input.Role}
		if s.maxPromptChars > 0 && len(text) > s.maxPromptChars {
			prompt.Truncated = true
			text = text[:s.maxPromptChars]
		}
		if s.redactPrompt {
			prompt.Redacted = true
			text = replayRedactPattern.ReplaceAllString(text, "[REDACTED]")
		}
		prompt.Text = text
		prompts = append(prompts, prompt)
	}
	return prompts
}

func (s *LocalReplayStore) readAllEvents() ([]ReplayEventRecord, error) {
	if s == nil {
		return []ReplayEventRecord{}, nil
	}

	s.mu.Lock()
	files := s.rotatedFilesLocked()
	s.mu.Unlock()

	events := make([]ReplayEventRecord, 0)
	for _, filePath := range files {
		loaded, err := readReplayFile(filePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		events = append(events, loaded...)
	}
	return events, nil
}

func readReplayFile(path string) ([]ReplayEventRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := make([]ReplayEventRecord, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event ReplayEventRecord
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		out = append(out, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *LocalReplayStore) rotateIfNeededLocked(incoming int64) error {
	fi, err := os.Stat(s.storagePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	if fi.Size()+incoming <= s.maxFileSizeBytes {
		return nil
	}

	for i := s.maxFiles - 1; i >= 1; i-- {
		current := fmt.Sprintf("%s.%d", s.storagePath, i)
		next := fmt.Sprintf("%s.%d", s.storagePath, i+1)
		if i == s.maxFiles-1 {
			_ = os.Remove(current)
			continue
		}
		if _, err := os.Stat(current); err == nil {
			if err := os.Rename(current, next); err != nil {
				return err
			}
		}
	}

	if _, err := os.Stat(s.storagePath); err == nil {
		if err := os.Rename(s.storagePath, s.storagePath+".1"); err != nil {
			return err
		}
	}
	return nil
}

func (s *LocalReplayStore) rotatedFilesLocked() []string {
	files := make([]string, 0, s.maxFiles+1)
	for i := s.maxFiles; i >= 1; i-- {
		files = append(files, fmt.Sprintf("%s.%d", s.storagePath, i))
	}
	files = append(files, s.storagePath)
	return files
}

func nextReplayID() string {
	seq := atomic.AddUint64(&replayIDCounter, 1)
	return fmt.Sprintf("rpl_%d_%d", time.Now().UTC().UnixNano(), seq)
}

func payloadHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func cloneReplayFindings(src []detector.Finding) []detector.Finding {
	if len(src) == 0 {
		return []detector.Finding{}
	}
	out := make([]detector.Finding, 0, len(src))
	for _, finding := range src {
		cp := finding
		if finding.Metadata != nil {
			cp.Metadata = make(map[string]string, len(finding.Metadata))
			for k, v := range finding.Metadata {
				cp.Metadata[k] = v
			}
		}
		out = append(out, cp)
	}
	return out
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
