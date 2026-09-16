// Package tpmkey does the TPM half of the prototype: it creates an unwrap key
// inside a node's TPM and uses it to recover a DEK.
//
// The key is created with FixedTPM|FixedParent and SensitiveDataOrigin, so its
// private half is generated in the TPM and can never be exported — not by root
// on the node, not by anyone holding the disk. Use of the key is gated by a
// PolicyPCR authorisation policy, and UserWithAuth is deliberately *off* so
// there is no password path around that policy.
package tpmkey

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/athalabs/openbao-tpm/internal/envelope"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// DefaultDevice is the TPM resource manager. Always prefer it over /dev/tpm0:
// the kernel multiplexes sessions and transient objects for us, which matters
// because Talos is using the same TPM for disk encryption.
const DefaultDevice = "/dev/tpmrm0"

// DefaultPCRs is what we bind the policy to. It returns a fresh slice: a
// package-level slice would be an appendable global.
//
// PCR 7 records SecureBoot state and the certificate that signed the loaded
// image. On this cluster that cert belongs to the Talos Image Factory, so PCR 7
// says "SecureBoot is on and a factory-signed image booted" — it does not
// distinguish our Talos from anyone else's. The machine binding comes from the
// key living in this TPM, not from the PCR value.
//
// PCR 7 is stable across Talos upgrades, which PCR 11 is not: Talos extends 11
// with UKI measurements and its own boot phases, so any upgrade would invalidate
// a policy bound to it. Binding 11 as well is a deliberate later step that comes
// with a re-seal-on-upgrade runbook.
func DefaultPCRs() []uint { return []uint{7} }

// Open connects to the TPM device.
func Open(path string) (transport.TPMCloser, error) {
	t, err := linuxtpm.Open(path)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: opening %s: %w", path, err)
	}
	return t, nil
}

func selection(pcrs []uint) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
		}},
	}
}

// srk creates the storage root key: a primary key in the owner hierarchy using
// the standard TCG template. It is deterministic — the same template under the
// same TPM seed always yields the same key — so we never have to persist it, and
// it costs no scarce NV space.
func srk(t transport.TPM) (*tpm2.CreatePrimaryResponse, func(), error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("tpmkey: creating SRK: %w", err)
	}
	flush := func() {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)
	}
	return rsp, flush, nil
}

// PolicyDigest computes the authorisation policy digest that a real policy
// session will produce for the current PCR values.
//
// It deliberately uses a *real* session rather than a trial one. A trial session
// does not read the PCRs: it folds in whatever pcrDigest the caller supplies, so
// the digest it yields only matches reality if the caller computed the PCR
// digest correctly and independently. Enrollment always happens on the machine
// being enrolled, with the PCRs already in the state we want to bind to, so
// asking the TPM directly removes a whole class of mismatch.
func PolicyDigest(t transport.TPM, pcrs []uint) ([]byte, error) {
	return policyDigest(t, pcrs, nil)
}

// TrialPolicyDigest computes the same digest with a trial session. pcrDigest is
// what the trial session is told the PCRs hash to; passing nil is what naive
// implementations do, and is exactly the case that disagrees with hardware.
// Kept for the `policydebug` command that documents the difference.
func TrialPolicyDigest(t transport.TPM, pcrs []uint, pcrDigest []byte) ([]byte, error) {
	return policyDigest(t, pcrs, pcrDigest, tpm2.Trial())
}

func policyDigest(t transport.TPM, pcrs []uint, pcrDigest []byte, opts ...tpm2.AuthOption) ([]byte, error) {
	sess, closer, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, opts...)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: starting policy session: %w", err)
	}
	defer func() { _ = closer() }()

	if _, err := (tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: pcrDigest},
		Pcrs:          selection(pcrs),
	}).Execute(t); err != nil {
		return nil, fmt.Errorf("tpmkey: PolicyPCR: %w", err)
	}
	digest, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: reading policy digest: %w", err)
	}
	return digest.PolicyDigest.Buffer, nil
}

// PCRDigest is the digest of the selected PCR values, computed the way the TPM
// does it: SHA-256 over the concatenated values in ascending PCR order.
func PCRDigest(t transport.TPM, pcrs []uint) ([]byte, error) {
	values, err := ReadPCRs(t, pcrs)
	if err != nil {
		return nil, err
	}
	ordered := append([]uint(nil), pcrs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	h := sha256.New()
	for _, pcr := range ordered {
		h.Write(values[pcr])
	}
	return h.Sum(nil), nil
}

// ReadPCRs returns the current SHA-256 values of the given PCRs.
func ReadPCRs(t transport.TPM, pcrs []uint) (map[uint][]byte, error) {
	out := make(map[uint][]byte, len(pcrs))
	// Read one at a time: the response groups digests per selection, and
	// per-PCR requests keep the mapping unambiguous.
	for _, pcr := range pcrs {
		rsp, err := tpm2.PCRRead{PCRSelectionIn: selection([]uint{pcr})}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("tpmkey: reading PCR %d: %w", pcr, err)
		}
		if len(rsp.PCRValues.Digests) == 0 {
			return nil, fmt.Errorf("tpmkey: PCR %d returned no value", pcr)
		}
		out[pcr] = rsp.PCRValues.Digests[0].Buffer
	}
	return out, nil
}

// Enroll creates the node's unwrap key and returns the artifact describing it.
func Enroll(t transport.TPM, node string, pcrs []uint) (*envelope.Artifact, error) {
	parent, flush, err := srk(t)
	if err != nil {
		return nil, err
	}
	defer flush()

	values, err := ReadPCRs(t, pcrs)
	if err != nil {
		return nil, err
	}
	policy, err := PolicyDigest(t, pcrs)
	if err != nil {
		return nil, err
	}

	created, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true, // never migratable off this TPM
				FixedParent:         true,
				SensitiveDataOrigin: true, // private half generated in the TPM
				// UserWithAuth off: USER-role use of this key requires a
				// policy session. With it on, an empty password would
				// authorise decryption and the PCR policy would be
				// decorative.
				UserWithAuth: false,
				NoDA:         true, // a crash-looping pod must not lock the TPM out
				Decrypt:      true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgOAEP,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{
						HashAlg: tpm2.TPMAlgSHA256,
					}),
				},
				KeyBits: 2048,
			}),
		}),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: creating unwrap key: %w", err)
	}

	pub, err := created.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: reading created public area: %w", err)
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: computing key name: %w", err)
	}
	rsaPub, err := rsaPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubPEM, err := envelope.EncodePublicKeyPEM(rsaPub)
	if err != nil {
		return nil, err
	}

	art := &envelope.Artifact{
		Version:      envelope.ArtifactVersion,
		Node:         node,
		KeyName:      hex.EncodeToString(name.Buffer),
		Public:       tpm2.Marshal(created.OutPublic),
		Private:      tpm2.Marshal(created.OutPrivate),
		PublicKeyPEM: pubPEM,
		PCRs:         pcrs,
		PCRValues:    values,
		PolicyDigest: policy,
		Parent:       "ECCSRKTemplate",
		CreatedAt:    time.Now().UTC(),
	}

	if err := attachEvidence(t, art, parent, created); err != nil {
		return nil, err
	}
	return art, nil
}

// Unwrap recovers a DEK that was wrapped to this node's unwrap key. It fails if
// the PCRs no longer match the policy, or if the artifact belongs to a different
// machine — in that case the TPM cannot even load the private blob.
func Unwrap(t transport.TPM, art *envelope.Artifact, wrappedDEK []byte) ([]byte, error) {
	if art.Version != envelope.ArtifactVersion {
		return nil, fmt.Errorf("tpmkey: artifact version %d, want %d", art.Version, envelope.ArtifactVersion)
	}

	parent, flush, err := srk(t)
	if err != nil {
		return nil, err
	}
	defer flush()

	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](art.Public)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: parsing artifact public area: %w", err)
	}
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](art.Private)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: parsing artifact private blob: %w", err)
	}

	loaded, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InPrivate:    *private,
		InPublic:     *public,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: loading unwrap key (wrong machine, or TPM state changed): %w", err)
	}
	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(t)
	}()

	sess, closer, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: starting policy session: %w", err)
	}
	defer func() { _ = closer() }()

	if _, err := (tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs:          selection(art.PCRs),
	}).Execute(t); err != nil {
		return nil, fmt.Errorf("tpmkey: PolicyPCR: %w", err)
	}

	decrypted, err := tpm2.RSADecrypt{
		KeyHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   sess,
		},
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: wrappedDEK},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: RSA decrypt (PCR policy not satisfied?): %w", err)
	}
	return decrypted.Message.Buffer, nil
}

func rsaPublicKey(pub *tpm2.TPMTPublic) (*rsa.PublicKey, error) {
	unique, err := pub.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: reading RSA modulus: %w", err)
	}
	if len(unique.Buffer) == 0 {
		return nil, errors.New("tpmkey: empty RSA modulus")
	}
	parms, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: reading RSA parameters: %w", err)
	}
	exponent := int(parms.Exponent)
	if exponent == 0 {
		exponent = 65537 // the TPM encodes the default exponent as zero
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(unique.Buffer), E: exponent}, nil
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
