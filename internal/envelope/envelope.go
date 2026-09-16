// Package envelope defines the two on-disk formats this tool produces.
//
// An Artifact is written once per node by `enroll`. It carries the public half
// of an RSA key that was created *inside* that node's TPM and can never leave
// it, plus the TPM-wrapped private blob (useless on any other machine) and the
// PCR policy that gates its use.
//
// An Envelope carries one payload encrypted under a random DEK, and that DEK
// wrapped once per enrolled node. Any enrolled node can recover the payload
// using its own TPM; no other machine can recover it at all. That per-node
// fan-out is what lets an OpenBao pod land on any of the nodes rather than
// being pinned to one.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Versions of the two formats. Both are written into every file so a future
// reader can refuse what it does not understand.
const (
	ArtifactVersion = 1
	EnvelopeVersion = 1
)

// formatAAD is bound into the AEAD so a payload cannot be replayed under a
// different format version. The recipient list is deliberately *not* part of it:
// adding a node must not require re-encrypting the payload.
var formatAAD = []byte("openbao-tpm/envelope/v1")

// aad combines the format tag with caller-supplied additional authenticated
// data. OpenBao's seal interface may pass its own AAD, and dropping it silently
// would discard an integrity binding the caller expects to hold.
func aad(extra []byte) []byte {
	if len(extra) == 0 {
		return formatAAD
	}
	out := make([]byte, 0, len(formatAAD)+1+len(extra))
	out = append(out, formatAAD...)
	out = append(out, '/')
	return append(out, extra...)
}

// Artifact is the result of enrolling one node. Everything in it is public
// except nothing: the private blob is encrypted to that node's TPM seed, so the
// whole file can be committed to git. It is still worth keeping out of a public
// repo, since it names your nodes and their PCR state.
type Artifact struct {
	Version int    `json:"version"`
	Node    string `json:"node"`
	// KeyName is the TPM Name (a digest over the public area) of the unwrap
	// key. It identifies a recipient independently of the node's hostname.
	KeyName string `json:"key_name"`
	// Public and Private are the marshalled TPM2B_PUBLIC / TPM2B_PRIVATE of
	// the unwrap key, to be loaded under the node's SRK.
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
	// PublicKeyPEM is the same public key in a form Go can encrypt to
	// without a TPM present.
	PublicKeyPEM string `json:"public_key_pem"`
	// PCRs are the PCR indices (SHA-256 bank) the key's policy is bound to,
	// and PCRDigest is their value at enrollment time, recorded so a later
	// mismatch can be diagnosed rather than guessed at.
	PCRs      []uint `json:"pcrs"`
	PCRDigest []byte `json:"pcr_digest"`
	Parent    string `json:"parent"`

	// The evidence half of the artifact. EKPublic is the marshalled public
	// area of the node's endorsement key — the TPM's identity, which is what
	// gets pinned. AKPublic/AKName are the attestation key that signed
	// CertifyInfo, a TPM-produced statement about the unwrap key.
	//
	// A verifier checks the signature offline, but only a credential
	// activation against EKPublic proves the AK lives in the TPM we mean; see
	// tpmkey.NewChallenge.
	EKPublic         []byte `json:"ek_public,omitempty"`
	EKName           []byte `json:"ek_name,omitempty"`
	AKPublic         []byte `json:"ak_public,omitempty"`
	AKName           []byte `json:"ak_name,omitempty"`
	CertifyInfo      []byte `json:"certify_info,omitempty"`
	CertifySignature []byte `json:"certify_signature,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// RSAPublicKey parses PublicKeyPEM.
func (a *Artifact) RSAPublicKey() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(a.PublicKeyPEM))
	if block == nil {
		return nil, errors.New("artifact: public_key_pem is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("artifact: parsing public key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("artifact: public key is %T, want RSA", key)
	}
	return rsaKey, nil
}

// EncodePublicKeyPEM renders a public key for an Artifact.
func EncodePublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("envelope: marshalling public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// Recipient is one node's wrapped copy of the DEK.
type Recipient struct {
	Node       string `json:"node"`
	KeyName    string `json:"key_name"`
	WrappedDEK []byte `json:"wrapped_dek"`
}

// Envelope is the sealed blob.
type Envelope struct {
	Version    int         `json:"version"`
	Nonce      []byte      `json:"nonce"`
	Ciphertext []byte      `json:"ciphertext"`
	Recipients []Recipient `json:"recipients"`
}

// Wrap encrypts plaintext under a fresh DEK and wraps that DEK to every
// recipient's TPM-resident public key. No TPM is needed here: wrapping is
// public-key only, which is why sealing works from a laptop or from a pod that
// happens to be scheduled anywhere.
func Wrap(plaintext, extraAAD []byte, recipients []Artifact) (*Envelope, error) {
	if len(recipients) == 0 {
		return nil, errors.New("envelope: no recipients")
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("envelope: generating DEK: %w", err)
	}

	aead, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("envelope: generating nonce: %w", err)
	}

	env := &Envelope{
		Version:    EnvelopeVersion,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, aad(extraAAD)),
	}

	for i := range recipients {
		pub, err := recipients[i].RSAPublicKey()
		if err != nil {
			return nil, err
		}
		// No OAEP label: TPM2_RSA_Decrypt requires a null-terminated label
		// and the empty label is the one value both sides agree on without
		// extra ceremony.
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, nil)
		if err != nil {
			return nil, fmt.Errorf("envelope: wrapping DEK for %s: %w", recipients[i].Node, err)
		}
		env.Recipients = append(env.Recipients, Recipient{
			Node:       recipients[i].Node,
			KeyName:    recipients[i].KeyName,
			WrappedDEK: wrapped,
		})
	}
	return env, nil
}

// RecipientFor returns the entry wrapped to the given TPM key name.
func (e *Envelope) RecipientFor(keyName string) (*Recipient, error) {
	for i := range e.Recipients {
		if e.Recipients[i].KeyName == keyName {
			return &e.Recipients[i], nil
		}
	}
	return nil, fmt.Errorf("envelope: no recipient for key %s (this envelope was not wrapped to this machine)", keyName)
}

// Open decrypts the payload with a DEK recovered from a TPM.
func (e *Envelope) Open(dek, extraAAD []byte) ([]byte, error) {
	if e.Version != EnvelopeVersion {
		return nil, fmt.Errorf("envelope: version %d, want %d", e.Version, EnvelopeVersion)
	}
	aead, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, e.Nonce, e.Ciphertext, aad(extraAAD))
	if err != nil {
		return nil, fmt.Errorf("envelope: opening payload: %w", err)
	}
	return plaintext, nil
}

func newAEAD(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: bad DEK: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: initialising GCM: %w", err)
	}
	return aead, nil
}
