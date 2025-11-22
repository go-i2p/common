package common

import "testing"

func TestVersionConstants(t *testing.T) {
	tests := []struct {
		name     string
		expected interface{}
		actual   interface{}
	}{
		{"I2P_SPEC_VERSION", "0.9.67", I2P_SPEC_VERSION},
		{"I2P_SPEC_MAJOR", 0, I2P_SPEC_MAJOR},
		{"I2P_SPEC_MINOR", 9, I2P_SPEC_MINOR},
		{"I2P_SPEC_PATCH", 67, I2P_SPEC_PATCH},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.actual != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.actual, tt.expected)
			}
		})
	}
}
