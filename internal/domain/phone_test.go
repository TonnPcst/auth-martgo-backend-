package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizePhone(t *testing.T) {
	valid := map[string]string{
		"2055551234":        "2055551234",
		"02055551234":       "2055551234",
		"020 5555 1234":     "2055551234",
		"+856 20 5555-1234": "2055551234",
		"8562055551234":     "2055551234",
		"030 555 1234":      "305551234",
		"+856 (30) 5551234": "305551234",
	}
	for in, want := range valid {
		got, err := NormalizePhone(in)
		if assert.NoError(t, err, in) {
			assert.Equal(t, want, got, in)
		}
	}

	for _, in := range []string{"", "12345", "205555123", "20555512345", "3055512345", "2055551abc", "+66 81 234 5678"} {
		_, err := NormalizePhone(in)
		assert.ErrorIs(t, err, ErrInvalidPhone, in)
	}
}
