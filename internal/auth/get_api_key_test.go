package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErrMsg string
	}{
		{
			name:       "missing header",
			headers:    http.Header{},
			wantErrMsg: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:       "malformed header",
			headers:    http.Header{"Authorization": []string{"Bearer abc"}},
			wantErrMsg: "malformed authorization header",
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey abc123"}},
			wantKey: "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}

			if tt.wantErrMsg == "" {
				if gotErr != nil {
					t.Fatalf("expected no error, got %v", gotErr)
				}
				return
			}

			if gotErr == nil {
				t.Fatalf("expected error %q, got nil", tt.wantErrMsg)
			}

			if gotErr.Error() != tt.wantErrMsg {
				t.Fatalf("expected error %q, got %q", tt.wantErrMsg, gotErr.Error())
			}
		})
	}
}
