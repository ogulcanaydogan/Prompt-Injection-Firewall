package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

type replayDetector struct{}

func (d *replayDetector) ID() string  { return "replay-detector" }
func (d *replayDetector) Ready() bool { return true }
func (d *replayDetector) Scan(ctx context.Context, input detector.ScanInput) (*detector.ScanResult, error) {
	if strings.Contains(strings.ToLower(input.Text), "attack") {
		return &detector.ScanResult{
			Clean: false,
			Score: 0.9,
			Findings: []detector.Finding{{
				RuleID:      "R-1",
				Category:    detector.CategoryPromptInjection,
				Severity:    detector.SeverityHigh,
				Description: "attack",
				MatchedText: input.Text,
			}},
		}, nil
	}
	return &detector.ScanResult{Clean: true, Score: 0}, nil
}

func TestLocalReplayStore_RecordListGetAndRescan(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "events.jsonl")
	storeIface, err := NewLocalReplayStore(ReplayOptions{
		Enabled:             true,
		StoragePath:         storePath,
		MaxFileSizeMB:       5,
		MaxFiles:            3,
		RedactPromptContent: false,
		MaxPromptChars:      1024,
	}, nil)
	require.NoError(t, err)
	store, ok := storeIface.(*LocalReplayStore)
	require.True(t, ok)

	err = store.Record(ReplayCaptureInput{
		Tenant:    "tenant-a",
		EventType: ReplayEventTypeBlock,
		Decision:  "block",
		Score:     0.91,
		Threshold: 0.5,
		Findings: []detector.Finding{{
			RuleID:      "R-1",
			Category:    detector.CategoryPromptInjection,
			Severity:    detector.SeverityHigh,
			Description: "blocked",
			MatchedText: "attack payload",
		}},
		RequestMeta: ReplayRequestMeta{
			Method:    "POST",
			Path:      "/v1/chat/completions",
			Target:    "https://api.openai.com",
			ClientKey: "10.0.0.1",
		},
		Body:   []byte(`{"messages":[{"role":"user","content":"attack payload"}]}`),
		Inputs: []detector.ScanInput{{Role: "user", Text: "attack payload"}},
	})
	require.NoError(t, err)

	list, err := store.List(ReplayListFilter{})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, ReplayEventTypeBlock, list[0].EventType)
	assert.Equal(t, "tenant-a", list[0].Tenant)
	assert.NotEmpty(t, list[0].PayloadHash)

	event, err := store.Get(list[0].ReplayID)
	require.NoError(t, err)
	require.NotNil(t, event)
	assert.Equal(t, "block", event.Decision)
	require.Len(t, event.Prompts, 1)
	assert.Equal(t, "attack payload", event.Prompts[0].Text)

	rescan, err := store.Rescan(context.Background(), list[0].ReplayID, &replayDetector{})
	require.NoError(t, err)
	require.NotNil(t, rescan)
	assert.True(t, rescan.RescanPossible)
	assert.False(t, rescan.Clean)
	assert.Equal(t, "detect", rescan.Decision)
	assert.GreaterOrEqual(t, rescan.FindingsCount, 1)
}

func TestLocalReplayStore_RedactionAndRotation(t *testing.T) {
	tmp := t.TempDir()
	storePath := filepath.Join(tmp, "events.jsonl")
	storeIface, err := NewLocalReplayStore(ReplayOptions{
		Enabled:             true,
		StoragePath:         storePath,
		MaxFileSizeMB:       1,
		MaxFiles:            2,
		RedactPromptContent: true,
		MaxPromptChars:      700000,
	}, nil)
	require.NoError(t, err)
	store := storeIface.(*LocalReplayStore)

	largePrompt := strings.Repeat("A", 600000) + " api_key=secret-token"
	for i := 0; i < 3; i++ {
		err = store.Record(ReplayCaptureInput{
			Tenant:    "default",
			EventType: ReplayEventTypeFlag,
			Decision:  "flag",
			RequestMeta: ReplayRequestMeta{
				Method: "POST",
				Path:   "/v1/chat/completions",
			},
			Inputs: []detector.ScanInput{{Role: "user", Text: largePrompt}},
		})
		require.NoError(t, err)
	}

	_, err = os.Stat(storePath + ".1")
	require.NoError(t, err)

	list, err := store.List(ReplayListFilter{Limit: 1})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.NotEmpty(t, list[0].Prompts)
	assert.True(t, list[0].Prompts[0].Redacted)
	assert.NotContains(t, list[0].Prompts[0].Text, "secret-token")
}

func TestNoopReplayStore(t *testing.T) {
	store := NewNoopReplayStore()
	require.False(t, store.Enabled())
	assert.NoError(t, store.Record(ReplayCaptureInput{}))
	list, err := store.List(ReplayListFilter{})
	require.NoError(t, err)
	assert.Empty(t, list)
	_, err = store.Get("x")
	require.Error(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = store.Rescan(ctx, "x", &replayDetector{})
	require.Error(t, err)
}
