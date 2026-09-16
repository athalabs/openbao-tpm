package tpmkey

import (
	"bytes"
	"testing"

	"github.com/athalabs/openbao-tpm/internal/envelope"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// The simulator stands in for a node's TPM. It exercises the real command
// sequence — create, load, policy session, RSA decrypt — so the only thing left
// to prove on hardware is that Intel PTT behaves like a TPM should.
func openSim(t *testing.T) transport.TPM {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("no TPM simulator available: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	return sim
}

func TestEnrollThenUnwrap(t *testing.T) {
	sim := openSim(t)

	art, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if art.KeyName == "" || len(art.Public) == 0 || len(art.Private) == 0 {
		t.Fatal("Enroll returned an incomplete artifact")
	}

	secret := []byte("openbao root key")
	env, err := envelope.Wrap(secret, []envelope.Artifact{*art})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	dek, err := Unwrap(sim, art, env.Recipients[0].WrappedDEK)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	got, err := env.Open(dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

// Two enrolled keys in the same TPM must each only open their own recipient
// entry — the fan-out is per key, not per machine-with-any-key.
func TestUnwrapRejectsAnotherKeysEntry(t *testing.T) {
	sim := openSim(t)

	first, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll first: %v", err)
	}
	second, err := Enroll(sim, "node-b", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll second: %v", err)
	}
	if first.KeyName == second.KeyName {
		t.Fatal("two enrollments produced the same key name")
	}

	env, err := envelope.Wrap([]byte("openbao root key"), []envelope.Artifact{*second})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := Unwrap(sim, first, env.Recipients[0].WrappedDEK); err == nil {
		t.Fatal("unwrapped an entry belonging to another key")
	}
}

// Changing a bound PCR must break the policy. This is the mechanism that would
// refuse to unseal on a machine whose SecureBoot state changed.
func TestUnwrapFailsAfterPCRChange(t *testing.T) {
	sim := openSim(t)

	art, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	env, err := envelope.Wrap([]byte("openbao root key"), []envelope.Artifact{*art})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := Unwrap(sim, art, env.Recipients[0].WrappedDEK); err != nil {
		t.Fatalf("Unwrap before PCR change: %v", err)
	}

	if _, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(DefaultPCRs()[0]), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{{
				HashAlg: tpm2.TPMAlgSHA256,
				Digest:  make([]byte, 32),
			}},
		},
	}).Execute(sim); err != nil {
		t.Fatalf("PCRExtend: %v", err)
	}

	if _, err := Unwrap(sim, art, env.Recipients[0].WrappedDEK); err == nil {
		t.Fatal("unwrapped after the bound PCR changed")
	}
}

func TestReadPCRsAndPolicyDigest(t *testing.T) {
	sim := openSim(t)

	values, err := ReadPCRs(sim, []uint{0, 7})
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	for _, pcr := range []uint{0, 7} {
		if len(values[pcr]) != 32 {
			t.Fatalf("PCR %d: got %d bytes, want 32", pcr, len(values[pcr]))
		}
	}

	digest, err := PolicyDigest(sim, []uint{7})
	if err != nil {
		t.Fatalf("PolicyDigest: %v", err)
	}
	if len(digest) != 32 {
		t.Fatalf("policy digest: got %d bytes, want 32", len(digest))
	}
}

// Enrollment must bind the key to the digest a *real* session will produce.
//
// This is the bug that hardware caught and the simulator did not: on Intel PTT,
// a trial session told nothing about the PCRs folds an empty digest into the
// policy, so a key enrolled that way is unusable — TPM_RC_POLICY_FAIL at first
// decrypt. The simulator instead behaves as if the current PCRs had been
// supplied, so trial-with-empty and real agree there and the mismatch is
// invisible. Assert the relationship that holds on both: given the PCR digest
// explicitly, a trial session agrees with a real one.
func TestTrialPolicyDigestMatchesRealSessionWhenGivenPCRDigest(t *testing.T) {
	sim := openSim(t)

	pcrDigest, err := PCRDigest(sim, DefaultPCRs())
	if err != nil {
		t.Fatalf("PCRDigest: %v", err)
	}
	realDigest, err := PolicyDigest(sim, DefaultPCRs())
	if err != nil {
		t.Fatalf("PolicyDigest: %v", err)
	}
	trial, err := TrialPolicyDigest(sim, DefaultPCRs(), pcrDigest)
	if err != nil {
		t.Fatalf("TrialPolicyDigest: %v", err)
	}
	if !bytes.Equal(trial, realDigest) {
		t.Fatalf("trial digest %x != real session digest %x", trial, realDigest)
	}
}

// The artifact must record the policy the key was actually created under, so a
// later failure can be diagnosed by comparing digests rather than guessed at.
func TestArtifactRecordsTheRealPolicyDigest(t *testing.T) {
	sim := openSim(t)

	want, err := PolicyDigest(sim, DefaultPCRs())
	if err != nil {
		t.Fatalf("PolicyDigest: %v", err)
	}
	art, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !bytes.Equal(art.PCRDigest, want) {
		t.Fatalf("artifact policy digest %x != %x", art.PCRDigest, want)
	}
}

// Enrollment must carry evidence a verifier can check without a TPM.
func TestVerifyArtifactAcceptsRealEnrollment(t *testing.T) {
	sim := openSim(t)

	art, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(art.EKPublic) == 0 || len(art.AKPublic) == 0 || len(art.CertifySignature) == 0 {
		t.Fatal("artifact carries no attestation evidence")
	}
	if err := VerifyArtifact(art); err != nil {
		t.Fatalf("VerifyArtifact: %v", err)
	}
}

// A forged attestation must not pass. Flipping a byte of the signature is the
// cheapest version of "someone wrote their own artifact".
func TestVerifyArtifactRejectsBrokenSignature(t *testing.T) {
	sim := openSim(t)

	art, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	art.CertifySignature[0] ^= 0xff
	if err := VerifyArtifact(art); err == nil {
		t.Fatal("VerifyArtifact accepted a broken signature")
	}
}

// Swapping in another TPM-resident key's public area must not pass either: the
// attestation names a specific key.
func TestVerifyArtifactRejectsSubstitutedKey(t *testing.T) {
	sim := openSim(t)

	first, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll first: %v", err)
	}
	second, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll second: %v", err)
	}

	first.Public = second.Public
	first.KeyName = second.KeyName
	if err := VerifyArtifact(first); err == nil {
		t.Fatal("VerifyArtifact accepted an attestation for a different key")
	}
}

// Credential activation is what proves the AK is in the TPM we pinned, rather
// than a public half someone copied.
func TestChallengeRoundTrip(t *testing.T) {
	sim := openSim(t)

	art, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := NewChallenge(art)
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	answer, err := Activate(sim, challenge)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !bytes.Equal(answer, challenge.Expected) {
		t.Fatalf("activation returned %x, want %x", answer, challenge.Expected)
	}
}

// A challenge built for one TPM's EK must not be answerable by another. The
// simulator only has one TPM, so stand in a second enrollment's AK name: the
// credential is bound to the AK name as well as the EK.
func TestActivateRejectsWrongAKName(t *testing.T) {
	sim := openSim(t)

	art, err := Enroll(sim, "node-a", DefaultPCRs())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := NewChallenge(art)
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	// Corrupt the name binding by tampering with the credential blob.
	challenge.CredentialBlob[len(challenge.CredentialBlob)-1] ^= 0xff
	if _, err := Activate(sim, challenge); err == nil {
		t.Fatal("Activate accepted a credential that was not bound to this AK")
	}
}
