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

func TestCheckURL(t *testing.T) {
	// Test cases for URL validation
	testCases := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "Valid HTTP URL",
			url:         "http://example.com",
			expectError: false,
		},
		{
			name:        "Valid HTTPS URL",
			url:         "https://example.com",
			expectError: false,
		},
		{
			name:        "Valid URL with port",
			url:         "http://example.com:8080",
			expectError: false,
		},
		{
			name:        "Valid URL with path",
			url:         "http://example.com/path",
			expectError: false,
		},
		{
			name:        "Missing scheme",
			url:         "example.com",
			expectError: true,
		},
		{
			name:        "Invalid scheme",
			url:         "ftp://example.com",
			expectError: false,
		},
		{
			name:        "Missing host",
			url:         "http://",
			expectError: true,
		},
		{
			name:        "Empty URL",
			url:         "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckURL(tc.url)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for URL '%s', got nil", tc.url)
			} else if !tc.expectError && err != nil {
				t.Errorf("Unexpected error for URL '%s': %v", tc.url, err)
			}
		})
	}
}
