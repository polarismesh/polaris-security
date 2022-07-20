package util

import (
	"testing"
)

func TestExtractJwtToken(t *testing.T) {
	testCases := map[string]struct {
		input          string
		expectedOutput string
	}{
		"No bearer prefix": {
			input:          "abc",
			expectedOutput: "abc",
		},
		"Has bearer prefix": {
			input:          "Bearer abcd",
			expectedOutput: "abcd",
		},
		"Bearer prefix case insensitive": {
			input:          "BeArEr abcd",
			expectedOutput: "abcd",
		},
	}
	for id, c := range testCases {
		output := ExtractJwtToken(c.input)
		if output != c.expectedOutput {
			t.Errorf("Case %s: expecting output to be (%s) but got (%s)", id, c.expectedOutput, output)
		}
	}
}
