package domain

import (
	"errors"
	"strings"
)

var ErrInvalidPhone = errors.New("phone must be a Lao mobile number such as 020 5555 1234 or 030 555 1234")

// NormalizePhone converts a Lao mobile number to its canonical digits.
//
// ENG: Removes spaces, dashes, dots, brackets and "+", then the 856 country code and a
// leading 0. The result must be 20 followed by 8 digits, or 30 followed by 7 digits.
// Example: "+856 20 5555-1234" becomes "2055551234".
// LAO: ປັບເບີໂທລາວໃຫ້ເປັນຮູບແບບມາດຕະຖານ — ຕັດ 856 ແລະ 0 ອອກ, ຕ້ອງເປັນ 20xxxxxxxx ຫຼື 30xxxxxxx.
//
// @param s - phone number as typed by the user
// @returns the normalized digits, or ErrInvalidPhone
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
