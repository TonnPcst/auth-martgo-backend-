package domain

import (
	"errors"
	"strings"
)

var ErrInvalidPhone = errors.New("phone must be a Lao mobile number such as 020 5555 1234 or 030 555 1234")

func NormalizePhone(s string) (string, error) {
	digits := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '.', '(', ')', '+':
			return -1
		}
		return r
	}, s)
	digits = strings.TrimPrefix(digits, "856")
	digits = strings.TrimPrefix(digits, "0")

	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", ErrInvalidPhone
		}
	}
	switch {
	case strings.HasPrefix(digits, "20") && len(digits) == 10,
		strings.HasPrefix(digits, "30") && len(digits) == 9:
		return digits, nil
	}
	return "", ErrInvalidPhone
}
