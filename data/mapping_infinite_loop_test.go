package data

import (
	"testing"
	"time"
)

// TestMappingInfiniteLoopProtection verifies that the parser doesn't hang
// on malformed data that could cause infinite loops.
func TestMappingInfiniteLoopProtection(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
		description string
	}{
		{
			name: "malformed_repeated_data_no_progress",
			// Create data that could loop: size field + repeating pattern that never advances
			data: func() []byte {
				// Size: 100 bytes (but we'll craft data that doesn't advance)
				sizeInt, _ := NewIntegerFromInt(100, 2)
				data := sizeInt.Bytes()

				// Add a malformed key-value pair that might not consume bytes properly
				// Key length 5, but actual key is only 3 bytes (missing data)
				data = append(data, byte(5))          // key length
				data = append(data, []byte("abc")...) // only 3 bytes, not 5
				// No '=' delimiter, no value, no ';' delimiter
				// This creates incomplete data that the old parser might loop on

				return data
			}(),
			expectError: true,
			description: "data too short for declared string length",
		},
		{
			name: "excessive_pairs_limit",
			// Create valid data but with MAX_MAPPING_PAIRS+1 pairs
			data: func() []byte {
				// Build a mapping with more than MAX_MAPPING_PAIRS
				gomap := make(map[string]string)
				for i := 0; i < MAX_MAPPING_PAIRS+10; i++ {
					// Create unique keys
					key := string(rune('a'+(i%26))) + string(rune('a'+((i/26)%26))) + string(rune('0'+(i%10)))
					val := "v"
					gomap[key] = val
				}
				mapping, _ := GoMapToMapping(gomap)
				return mapping.Data()
			}(),
			expectError: true,
			description: "exceeds MAX_MAPPING_PAIRS limit",
		},
		{
			name: "missing_delimiter_creates_no_progress",
			data: func() []byte {
				// Size: 50 bytes
				sizeInt, _ := NewIntegerFromInt(50, 2)
				data := sizeInt.Bytes()

				// Valid key
				data = append(data, byte(3))
				data = append(data, []byte("key")...)
				// Missing '=' delimiter - should cause error and stop
				data = append(data, byte(5)) // This looks like next key length
				data = append(data, []byte("value")...)

				return data
			}(),
			expectError: true,
			description: "missing equals delimiter",
		},
		{
			name: "truncated_data_at_value",
			data: func() []byte {
				// Size: 100 bytes (but actual data is truncated)
				sizeInt, _ := NewIntegerFromInt(100, 2)
				data := sizeInt.Bytes()

				// Valid key
				data = append(data, byte(3))
				data = append(data, []byte("key")...)
				data = append(data, MAPPING_EQUALS_DELIMITER)

				// Value length claims 50 bytes but we only provide 5
				data = append(data, byte(50))
				data = append(data, []byte("short")...)
				// No semicolon, truncated

				return data
			}(),
			expectError: true,
			description: "truncated value data",
		},
		{
			name: "valid_mapping_within_limits",
			data: func() []byte {
				// Create a valid mapping with reasonable number of pairs
				gomap := make(map[string]string)
				for i := 0; i < 10; i++ {
					key := string(rune('a' + i))
					val := string(rune('0' + i))
					gomap[key] = val
				}
				mapping, _ := GoMapToMapping(gomap)
				return mapping.Data()
			}(),
			expectError: false,
			description: "valid mapping should parse without error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a channel to detect if parsing hangs
			done := make(chan struct{})
			var mapping Mapping
			var errs []error

			go func() {
				defer close(done)
				mapping, _, errs = ReadMapping(tt.data)
			}()

			// Wait for completion with timeout
			select {
			case <-done:
				// Parse completed
				if tt.expectError && len(errs) == 0 {
					t.Errorf("Expected error for %s, but got none", tt.description)
				}
				if !tt.expectError && len(errs) > 0 {
					t.Errorf("Expected no error for %s, but got: %v", tt.description, errs)
				}

				// Verify we didn't parse an excessive number of pairs
				vals := mapping.Values()
				if len(vals) > MAX_MAPPING_PAIRS {
					t.Errorf("Parsed more than MAX_MAPPING_PAIRS: got %d pairs", len(vals))
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("Parser hung (infinite loop detected) on: %s", tt.description)
			}
		})
	}
}

// TestMappingPairCountLimit tests that the MAX_MAPPING_PAIRS limit is enforced
func TestMappingPairCountLimit(t *testing.T) {
	// Create mapping data with exactly MAX_MAPPING_PAIRS
	gomap := make(map[string]string)
	for i := 0; i < MAX_MAPPING_PAIRS; i++ {
		// Use unique keys to avoid duplicate key errors
		key := string(rune('a'+(i%26))) + string(rune('a'+((i/26)%26))) + string(rune('0'+(i%10)))
		val := "v"
		gomap[key] = val
	}

	mapping, err := GoMapToMapping(gomap)
	if err != nil {
		t.Fatalf("Failed to create mapping: %v", err)
	}
	data := mapping.Data()

	// This should parse successfully
	_, _, errs := ReadMapping(data)
	if len(errs) > 0 {
		t.Errorf("Valid mapping with MAX_MAPPING_PAIRS should parse: %v", errs)
	}
}

// TestForwardProgressDetection tests that the parser detects when it's not making progress
func TestForwardProgressDetection(t *testing.T) {
	// This is a theoretical test - in practice, the bounds checks should prevent
	// most no-progress scenarios, but this tests the explicit check

	// Create data that's short and malformed
	sizeInt, _ := NewIntegerFromInt(20, 2)
	data := sizeInt.Bytes()

	// Add just enough bytes to pass minimum check but create parsing issues
	data = append(data, []byte{3, 'a', 'b', 'c', '=', 1, 'x', ';'}...)

	_, _, errs := ReadMapping(data)

	// Should complete (not hang) whether it succeeds or fails
	// The important thing is it returns rather than looping forever
	t.Logf("Parsing completed with %d errors", len(errs))
}
