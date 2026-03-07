package webhook

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const skipValidationAnnotation = "pif.io/skip-validation"

var supportedKinds = map[string]struct{}{
	"Pod":         {},
	"Deployment":  {},
	"StatefulSet": {},
	"Job":         {},
	"CronJob":     {},
}

type validator struct {
	pifHostPattern string
	pifHostRegex   *regexp.Regexp
}

func newValidator(pattern string) (*validator, error) {
	if strings.TrimSpace(pattern) == "" {
		pattern = `(?i)pif-proxy`
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pif host pattern: %w", err)
	}
	return &validator{
		pifHostPattern: pattern,
		pifHostRegex:   re,
	}, nil
}

func (v *validator) validate(kind string, raw json.RawMessage) (bool, string, error) {
	if _, ok := supportedKinds[kind]; !ok {
		return true, "", nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false, "", fmt.Errorf("parsing object: %w", err)
	}

	if hasSkipValidationAnnotation(obj) {
		return true, "", nil
	}

	env := collectEnvVars(kind, obj)
	hasOpenAIKey := hasEnvVar(env, "OPENAI_API_KEY")
	hasAnthropicKey := hasEnvVar(env, "ANTHROPIC_API_KEY")
	if !hasOpenAIKey && !hasAnthropicKey {
		return true, "", nil
	}

	if hasOpenAIKey {
		base := strings.TrimSpace(env["OPENAI_BASE_URL"])
		if !v.baseURLAllowed(base) {
			return false, "OPENAI_BASE_URL must route through PIF proxy", nil
		}
	}

	if hasAnthropicKey {
		base := strings.TrimSpace(env["ANTHROPIC_BASE_URL"])
		if !v.baseURLAllowed(base) {
			return false, "ANTHROPIC_BASE_URL must route through PIF proxy", nil
		}
	}

	return true, "", nil
}

func (v *validator) baseURLAllowed(baseURL string) bool {
	if baseURL == "" {
		return false
	}
	return v.pifHostRegex.MatchString(baseURL)
}

func hasSkipValidationAnnotation(obj map[string]interface{}) bool {
	annotationLocations := [][]string{
		{"metadata", "annotations"},
		{"spec", "template", "metadata", "annotations"},
		{"spec", "jobTemplate", "spec", "template", "metadata", "annotations"},
	}

	for _, path := range annotationLocations {
		value, ok := getNestedMapValue(obj, path...)
		if !ok {
			continue
		}
		annotations, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		if strings.EqualFold(fmt.Sprint(annotations[skipValidationAnnotation]), "true") {
			return true
		}
	}
	return false
}

func collectEnvVars(kind string, obj map[string]interface{}) map[string]string {
	result := make(map[string]string)
	podSpecPath := []string{"spec"}

	switch kind {
	case "Deployment", "StatefulSet", "Job":
		podSpecPath = []string{"spec", "template", "spec"}
	case "CronJob":
		podSpecPath = []string{"spec", "jobTemplate", "spec", "template", "spec"}
	}

	podSpecAny, ok := getNestedMapValue(obj, podSpecPath...)
	if !ok {
		return result
	}
	podSpec, ok := podSpecAny.(map[string]interface{})
	if !ok {
		return result
	}

	collectContainerEnv(podSpec["containers"], result)
	collectContainerEnv(podSpec["initContainers"], result)

	return result
}

func collectContainerEnv(containersAny interface{}, dst map[string]string) {
	containers, ok := containersAny.([]interface{})
	if !ok {
		return
	}

	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		envList, ok := container["env"].([]interface{})
		if !ok {
			continue
		}
		for _, e := range envList {
			envVar, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			name := strings.TrimSpace(fmt.Sprint(envVar["name"]))
			if name == "" {
				continue
			}
			value := strings.TrimSpace(fmt.Sprint(envVar["value"]))
			if _, exists := dst[name]; !exists {
				dst[name] = value
			}
		}
	}
}

func hasEnvVar(vars map[string]string, key string) bool {
	_, ok := vars[key]
	return ok
}

func getNestedMapValue(root map[string]interface{}, path ...string) (interface{}, bool) {
	var current interface{} = root
	for _, segment := range path {
		nextMap, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		next, ok := nextMap[segment]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}
