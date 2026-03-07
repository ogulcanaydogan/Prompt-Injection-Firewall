package webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateAdmissionRequest_TargetKinds(t *testing.T) {
	v, err := newValidator(`(?i)pif-proxy`)
	require.NoError(t, err)

	kinds := []string{"Pod", "Deployment", "StatefulSet", "Job", "CronJob"}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			raw := mustMarshal(t, objectForKind(kind, map[string]string{}, map[string]string{
				"OPENAI_API_KEY":  "secret",
				"OPENAI_BASE_URL": "https://external-llm.example.com/v1",
			}))

			allowed, message, err := evaluateAdmissionRequest(v, &AdmissionRequest{
				UID:       "uid-1",
				Operation: "CREATE",
				Kind:      GroupVersionKind{Kind: kind},
				Object:    raw,
			})
			require.NoError(t, err)
			assert.False(t, allowed)
			assert.Contains(t, message, "OPENAI_BASE_URL")
		})
	}
}

func TestEvaluateAdmissionRequest_AllowWhenPIFBaseURLMatches(t *testing.T) {
	v, err := newValidator(`(?i)pif-proxy`)
	require.NoError(t, err)

	raw := mustMarshal(t, objectForKind("Deployment", map[string]string{}, map[string]string{
		"OPENAI_API_KEY":  "secret",
		"OPENAI_BASE_URL": "http://pif-proxy.default.svc.cluster.local:8080/v1",
	}))

	allowed, _, err := evaluateAdmissionRequest(v, &AdmissionRequest{
		UID:       "uid-2",
		Operation: "UPDATE",
		Kind:      GroupVersionKind{Kind: "Deployment"},
		Object:    raw,
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestEvaluateAdmissionRequest_BypassAnnotation(t *testing.T) {
	v, err := newValidator(`(?i)pif-proxy`)
	require.NoError(t, err)

	raw := mustMarshal(t, objectForKind("Pod", map[string]string{
		skipValidationAnnotation: "true",
	}, map[string]string{
		"OPENAI_API_KEY": "secret",
	}))

	allowed, _, err := evaluateAdmissionRequest(v, &AdmissionRequest{
		UID:       "uid-3",
		Operation: "CREATE",
		Kind:      GroupVersionKind{Kind: "Pod"},
		Object:    raw,
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestValidateHandler_ResponseEnvelope(t *testing.T) {
	v, err := newValidator(`(?i)pif-proxy`)
	require.NoError(t, err)

	handler := validateHandler(v, nil)

	review := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       "uid-4",
			Operation: "CREATE",
			Kind:      GroupVersionKind{Kind: "Pod"},
			Object: mustMarshal(t, objectForKind("Pod", map[string]string{}, map[string]string{
				"OPENAI_API_KEY":  "secret",
				"OPENAI_BASE_URL": "https://pif-proxy:8080/v1",
			})),
		},
	}
	payload := mustMarshal(t, review)

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var got AdmissionReview
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.NotNil(t, got.Response)
	assert.Equal(t, "uid-4", got.Response.UID)
	assert.True(t, got.Response.Allowed)
}

func TestValidateHandler_MethodNotAllowed(t *testing.T) {
	v, err := newValidator(`(?i)pif-proxy`)
	require.NoError(t, err)
	handler := validateHandler(v, nil)

	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestValidateHandler_InvalidPayload(t *testing.T) {
	v, err := newValidator(`(?i)pif-proxy`)
	require.NoError(t, err)
	handler := validateHandler(v, nil)

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewBufferString("invalid-json"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestEvaluateAdmissionRequest_NonCreateUpdate(t *testing.T) {
	v, err := newValidator(`(?i)pif-proxy`)
	require.NoError(t, err)

	allowed, message, err := evaluateAdmissionRequest(v, &AdmissionRequest{
		UID:       "uid-5",
		Operation: "DELETE",
		Kind:      GroupVersionKind{Kind: "Pod"},
		Object: mustMarshal(t, objectForKind("Pod", nil, map[string]string{
			"OPENAI_API_KEY": "secret",
		})),
	})
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, "", message)
}

func TestStartServer_InvalidPattern(t *testing.T) {
	err := StartServer(ServerOptions{
		Listen:         ":-1",
		PIFHostPattern: "(",
	})
	require.Error(t, err)
}

func TestStartServer_InvalidListen(t *testing.T) {
	err := StartServer(ServerOptions{
		Listen:         ":-1",
		PIFHostPattern: `(?i)pif-proxy`,
	})
	require.Error(t, err)
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func objectForKind(kind string, annotations, env map[string]string) map[string]interface{} {
	containerEnv := make([]interface{}, 0, len(env))
	for k, v := range env {
		containerEnv = append(containerEnv, map[string]interface{}{
			"name":  k,
			"value": v,
		})
	}
	container := map[string]interface{}{
		"name": "app",
		"env":  containerEnv,
	}

	metadata := map[string]interface{}{
		"annotations": annotations,
	}

	podSpec := map[string]interface{}{
		"containers": []interface{}{container},
	}

	switch kind {
	case "Pod":
		return map[string]interface{}{
			"metadata": metadata,
			"spec":     podSpec,
		}
	case "CronJob":
		return map[string]interface{}{
			"metadata": metadata,
			"spec": map[string]interface{}{
				"jobTemplate": map[string]interface{}{
					"spec": map[string]interface{}{
						"template": map[string]interface{}{
							"metadata": metadata,
							"spec":     podSpec,
						},
					},
				},
			},
		}
	default:
		return map[string]interface{}{
			"metadata": metadata,
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"metadata": metadata,
					"spec":     podSpec,
				},
			},
		}
	}
}
