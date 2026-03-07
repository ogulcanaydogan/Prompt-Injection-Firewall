package webhook

import "encoding/json"

// AdmissionReview is the Kubernetes admission.k8s.io/v1 request/response envelope.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion,omitempty"`
	Kind       string             `json:"kind,omitempty"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest represents the incoming admission request.
type AdmissionRequest struct {
	UID       string           `json:"uid"`
	Kind      GroupVersionKind `json:"kind"`
	Operation string           `json:"operation"`
	Object    json.RawMessage  `json:"object"`
}

// GroupVersionKind identifies the target workload kind.
type GroupVersionKind struct {
	Group   string `json:"group,omitempty"`
	Version string `json:"version,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// AdmissionResponse tells the API server whether the request is allowed.
type AdmissionResponse struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Result  *Status `json:"status,omitempty"`
}

// Status mirrors admission response status fields.
type Status struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
