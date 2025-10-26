package auth

import "github.com/alexedwards/argon2id"

func HashPassword(password string) string {
	hashedPass, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return ""
	}
	return hashedPass
}

func CheckPasswordHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
