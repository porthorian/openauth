package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	encodingScheme = "pbkdf2"
	hashFunction   = "sha256"
)

type PBKDF2Options struct {
	Iterations int
	SaltBytes  int
	KeyBytes   int
}

type PBKDF2Hasher struct {
	options PBKDF2Options
}

func DefaultPBKDF2Options() PBKDF2Options {
	return PBKDF2Options{
		Iterations: 120000,
		SaltBytes:  16,
		KeyBytes:   32,
	}
}

func NewPBKDF2Hasher(options PBKDF2Options) *PBKDF2Hasher {
	defaults := DefaultPBKDF2Options()

	if options.Iterations <= 0 {
		options.Iterations = defaults.Iterations
	}
	if options.SaltBytes <= 0 {
		options.SaltBytes = defaults.SaltBytes
	}
	if options.KeyBytes <= 0 {
		options.KeyBytes = defaults.KeyBytes
	}

	return &PBKDF2Hasher{
		options: options,
	}
}

func (h *PBKDF2Hasher) Hash(password string) (string, error) {
	if h == nil {
		return "", ErrInvalidConfig
	}
	if password == "" {
		return "", ErrInvalidConfig
	}

	salt := make([]byte, h.options.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	derived := pbkdf2SHA256([]byte(password), salt, h.options.Iterations, h.options.KeyBytes)

	return fmt.Sprintf(
		"%s$%s$%d$%s$%s",
		encodingScheme,
		hashFunction,
		h.options.Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived),
	), nil
}

func (h *PBKDF2Hasher) Verify(password string, encodedHash string) (bool, error) {
	if h == nil {
		return false, ErrInvalidConfig
	}
	if password == "" {
		return false, ErrInvalidConfig
	}

	scheme, hashFn, iterations, salt, expected, err := parseEncodedHash(encodedHash)
	if err != nil {
		return false, err
	}
	if scheme != encodingScheme || hashFn != hashFunction {
		return false, ErrInvalidHash
	}

	candidate := pbkdf2SHA256([]byte(password), salt, iterations, len(expected))
	return subtle.ConstantTimeCompare(candidate, expected) == 1, nil
}

func parseEncodedHash(encodedHash string) (string, string, int, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 5 {
		return "", "", 0, nil, nil, ErrInvalidHash
	}

	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations <= 0 {
		return "", "", 0, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) == 0 {
		return "", "", 0, nil, nil, ErrInvalidHash
	}

	derived, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(derived) == 0 {
		return "", "", 0, nil, nil, ErrInvalidHash
	}

	return parts[0], parts[1], iterations, salt, derived, nil
}

func pbkdf2SHA256(password []byte, salt []byte, iterations int, keyLen int) []byte {
	const hashLen = sha256.Size

	blockCount := (keyLen + hashLen - 1) / hashLen
	derived := make([]byte, 0, blockCount*hashLen)
	blockInput := make([]byte, len(salt)+4)
	copy(blockInput, salt)

	for block := 1; block <= blockCount; block++ {
		binary.BigEndian.PutUint32(blockInput[len(salt):], uint32(block))

		u := hmacSHA256(password, blockInput)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {
			u = hmacSHA256(password, u)
			for x := range t {
				t[x] ^= u[x]
			}
		}

		derived = append(derived, t...)
	}

	return derived[:keyLen]
}

func hmacSHA256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}
