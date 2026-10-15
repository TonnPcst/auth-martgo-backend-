package token

import "golang.org/x/crypto/bcrypt"

// HashPassword hashes a password with bcrypt at the default cost.
//
// ENG: bcrypt only uses the first 72 bytes, which is why requests cap passwords at 72.
// LAO: hash ລະຫັດຜ່ານດ້ວຍ bcrypt.
//
// @param password - plain password
// @returns the hash, or an error
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// CheckPassword reports whether password matches a bcrypt hash.
//
// ENG: The comparison takes constant time.
// LAO: ກວດວ່າລະຫັດຜ່ານກົງກັບ hash ຫຼືບໍ່.
//
// @param hash - stored bcrypt hash
// @param password - plain password to check
// @returns true if they match
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
