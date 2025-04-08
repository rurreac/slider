package web

import (
	"net/http"
	"testing"
)

func TestGetTemplate(t *testing.T) {
	// Test cases for different web server templates
	testCases := []struct {
		name               string
		templateName       string
		expectedStatus     int
		expectedServerName string
		expectError        bool
	}{
		{
			name:               "Default template",
			templateName:       "default",
			expectedStatus:     http.StatusOK,
			expectedServerName: "",
			expectError:        false,
		},
		{
			name:               "Apache template",
			templateName:       "apache",
			expectedStatus:     http.StatusOK,
			expectedServerName: "Apache",
			expectError:        false,
		},
		{
			name:               "Nginx template",
			templateName:       "nginx",
			expectedStatus:     http.StatusOK,
			expectedServerName: "nginx",
			expectError:        false,
		},
		{
			name:               "IIS template",
			templateName:       "iis",
			expectedStatus:     http.StatusOK,
			expectedServerName: "Microsoft-IIS",
			expectError:        false,
		},
		{
			name:               "Tomcat template",
			templateName:       "tomcat",
			expectedStatus:     http.StatusNotFound,
			expectedServerName: "Apache Tomcat",
			expectError:        false,
		},
		{
			name:         "Invalid template",
			templateName: "invalid-template",
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			template, err := GetTemplate(tc.templateName)

			// Check error condition
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for template '%s', got nil", tc.templateName)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for template '%s': %v", tc.templateName, err)
			}

			// Check template properties
			if template.StatusCode != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, template.StatusCode)
			}

			if template.ServerHeader != tc.expectedServerName {
				t.Errorf("Expected server header '%s', got '%s'", tc.expectedServerName, template.ServerHeader)
			}

			// Ensure HTML content is not empty
			if template.HtmlTemplate == "" {
				t.Error("Template HTML content should not be empty")
			}
		})
	}
}
