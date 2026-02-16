package crypto

import "testing"

func TestPBKDF2HashAndVerify(t *testing.T) {
	hasher := NewPBKDF2Hasher(PBKDF2Options{
		Iterations: 1000,
		SaltBytes:  16,
		KeyBytes:   32,
	})

	encoded, err := hasher.Hash("secret-pass")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	ok, err := hasher.Verify("secret-pass", encoded)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !ok {
		t.Fatal("expected hash verification to succeed")
	}

	ok, err = hasher.Verify("wrong-pass", encoded)
	if err != nil {
		t.Fatalf("verify wrong password failed with error: %v", err)
	}
	if ok {
		t.Fatal("expected hash verification to fail for wrong password")
	}
}

func TestPBKDF2VerifyInvalidHash(t *testing.T) {
	hasher := NewPBKDF2Hasher(PBKDF2Options{
		Iterations: 1000,
		SaltBytes:  16,
		KeyBytes:   32,
	})

	ok, err := hasher.Verify("secret-pass", "invalid")
	if err == nil {
		t.Fatal("expected invalid hash error")
	}
	if ok {
		t.Fatal("expected verification to fail")
	}
}
