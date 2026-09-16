package envelope

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// softNode stands in for an enrolled node: on a real node the private key never
// leaves the TPM, but the wrapping side only ever touches the public half, so
// these tests exercise the real code path with software keys.
func softNode(t *testing.T, name string) (Artifact, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pem, err := EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	return Artifact{
		Version:      ArtifactVersion,
		Node:         name,
		KeyName:      "name-" + name,
		PublicKeyPEM: pem,
	}, key
}

func unwrapWith(t *testing.T, key *rsa.PrivateKey, wrapped []byte) []byte {
	t.Helper()
	dek, err := rsa.DecryptOAEP(sha256.New(), nil, key, wrapped, nil)
	if err != nil {
		t.Fatalf("unwrapping DEK: %v", err)
	}
	return dek
}

func TestWrapOpenEveryRecipient(t *testing.T) {
	a, aKey := softNode(t, "node-a")
	b, bKey := softNode(t, "node-b")
	secret := []byte("openbao root key")

	env, err := Wrap(secret, []Artifact{a, b})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(env.Recipients) != 2 {
		t.Fatalf("got %d recipients, want 2", len(env.Recipients))
	}

	for _, tc := range []struct {
		name string
		art  Artifact
		key  *rsa.PrivateKey
	}{{"node-a", a, aKey}, {"node-b", b, bKey}} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := env.RecipientFor(tc.art.KeyName)
			if err != nil {
				t.Fatalf("RecipientFor: %v", err)
			}
			got, err := env.Open(unwrapWith(t, tc.key, r.WrappedDEK))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, secret) {
				t.Fatalf("got %q, want %q", got, secret)
			}
		})
	}
}

// The property the whole design rests on: a machine that was not wrapped to
// cannot get at the payload, even holding the entire envelope.
func TestUnenrolledMachineIsRejected(t *testing.T) {
	a, _ := softNode(t, "node-a")
	stranger, strangerKey := softNode(t, "node-d")

	env, err := Wrap([]byte("openbao root key"), []Artifact{a})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if _, err := env.RecipientFor(stranger.KeyName); err == nil {
		t.Fatal("RecipientFor accepted an unenrolled key")
	}
	// Even if it tries the one entry that exists, its key cannot unwrap it.
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, strangerKey, env.Recipients[0].WrappedDEK, nil); err == nil {
		t.Fatal("an unenrolled key unwrapped the DEK")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	a, aKey := softNode(t, "node-a")
	env, err := Wrap([]byte("openbao root key"), []Artifact{a})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	env.Ciphertext[0] ^= 0xff

	dek := unwrapWith(t, aKey, env.Recipients[0].WrappedDEK)
	if _, err := env.Open(dek); err == nil {
		t.Fatal("Open accepted a tampered ciphertext")
	}
}

func TestVersionMismatchRefused(t *testing.T) {
	a, aKey := softNode(t, "node-a")
	env, err := Wrap([]byte("openbao root key"), []Artifact{a})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	dek := unwrapWith(t, aKey, env.Recipients[0].WrappedDEK)
	env.Version = 99
	if _, err := env.Open(dek); err == nil {
		t.Fatal("Open accepted an unknown envelope version")
	}
}

func TestWrapRequiresRecipients(t *testing.T) {
	if _, err := Wrap([]byte("x"), nil); err == nil {
		t.Fatal("Wrap accepted an empty recipient list")
	}
}
