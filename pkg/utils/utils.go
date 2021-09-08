package utils

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"log"
)

func HashPassword(password string) (string, string) {

	salt := generateSalt()
	var array []byte

	sha512h := sha512.New()

	array = append(array, []byte(password)...)
	array = append(array, []byte(salt)...)

	sha512h.Write(array)

	return salt, base64.RawStdEncoding.EncodeToString(sha512h.Sum(nil))
}

func generateSalt() string {

	const SaltLength = 5
	data := make([]byte, SaltLength)
	_, err := rand.Read(data)
	if err != nil {
		log.Fatal(err)
	}

	// Convert to a string

	return base64.RawStdEncoding.EncodeToString(data[:])[:5]
}

func ValidateUserStr(str string, mn, mx int) bool {
	var r = []rune(str)

	if len(r) < mn || len(r) > mx {
		return false
	}

	for _, val := range r {
		if (val >= 'а' && val <= 'я') || (val >= 'А' && val <= 'Я') {
			return false
		}
	}

	return true
}
