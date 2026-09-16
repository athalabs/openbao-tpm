package tpmwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/athalabs/openbao-tpm/internal/envelope"
	"github.com/athalabs/openbao-tpm/internal/tpmkey"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// simTPM stands in for a node's TPM. Enrolments made against it behave like
// separate nodes as far as the wrapper is concerned: each has its own key.
type simTPM struct {
	transport.TPMCloser
}

func newSim(t *testing.T) *simTPM {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("no TPM simulator available: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	return &simTPM{sim}
}

// Close is a no-op: the wrapper closes the device after each Decrypt, but the
// test keeps one simulator for the whole case.
func (s *simTPM) Close() error { return nil }

func enrolDir(t *testing.T, sim *simTPM, nodes ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, node := range nodes {
		art, err := tpmkey.Enroll(sim, node, tpmkey.DefaultPCRs())
		if err != nil {
			t.Fatalf("Enroll %s: %v", node, err)
		}
		data, err := json.Marshal(art)
		if err != nil {
			t.Fatalf("marshal %s: %v", node, err)
		}
		if err := os.WriteFile(filepath.Join(dir, node+".json"), data, 0o600); err != nil {
			t.Fatalf("write %s: %v", node, err)
		}
	}
	return dir
}

func configured(t *testing.T, sim *simTPM, dir, node string) *Wrapper {
	t.Helper()
	w := New()
	w.open = func(string) (transport.TPMCloser, error) { return sim, nil }
	if _, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"artifacts": dir,
		"node":      node,
	})); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	return w
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	sim := newSim(t)
	dir := enrolDir(t, sim, "node-a", "node-b")
	w := configured(t, sim, dir, "node-a")

	root := []byte("openbao root key")
	blob, err := w.Encrypt(context.Background(), root)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if blob.KeyInfo == nil || blob.KeyInfo.KeyId == "" {
		t.Fatal("blob carries no key ID")
	}

	got, err := w.Decrypt(context.Background(), blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, root) {
		t.Fatalf("got %q, want %q", got, root)
	}
}

// Every enrolled node must be able to open what any node wrapped. This is the
// property that lets an OpenBao pod move between machines.
func TestAnyEnrolledNodeCanDecrypt(t *testing.T) {
	sim := newSim(t)
	dir := enrolDir(t, sim, "node-a", "node-b")

	blob, err := configured(t, sim, dir, "node-a").Encrypt(context.Background(), []byte("openbao root key"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := configured(t, sim, dir, "node-b").Decrypt(context.Background(), blob)
	if err != nil {
		t.Fatalf("Decrypt on the other node: %v", err)
	}
	if string(got) != "openbao root key" {
		t.Fatalf("got %q", got)
	}
}

// A node that was not a recipient must fail with a clear error rather than a
// cryptographic one.
func TestDecryptRejectsUnenrolledNode(t *testing.T) {
	sim := newSim(t)
	shared := enrolDir(t, sim, "node-a")
	blob, err := configured(t, sim, shared, "node-a").Encrypt(context.Background(), []byte("openbao root key"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// A different node, enrolled elsewhere, holding the same blob.
	other := enrolDir(t, sim, "node-c")
	if _, err := configured(t, sim, other, "node-c").Decrypt(context.Background(), blob); err == nil {
		t.Fatal("an unenrolled node decrypted the blob")
	}
}

func TestSetConfigRequiresAnArtifactForThisNode(t *testing.T) {
	sim := newSim(t)
	dir := enrolDir(t, sim, "node-a")

	w := New()
	w.open = func(string) (transport.TPMCloser, error) { return sim, nil }
	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"artifacts": dir,
		"node":      "node-d",
	}))
	if err == nil {
		t.Fatal("SetConfig accepted a node with no artifact")
	}
}

// The key ID has to change when the enrolled set changes, since that is how
// OpenBao notices a blob was wrapped to a different set of machines.
func TestKeyIDTracksTheRecipientSet(t *testing.T) {
	sim := newSim(t)
	one := enrolDir(t, sim, "node-a")
	first, err := configured(t, sim, one, "node-a").KeyId(context.Background())
	if err != nil {
		t.Fatalf("KeyId: %v", err)
	}

	two := enrolDir(t, sim, "node-a", "node-b")
	second, err := configured(t, sim, two, "node-a").KeyId(context.Background())
	if err != nil {
		t.Fatalf("KeyId: %v", err)
	}
	if first == second {
		t.Fatal("key ID did not change when a node was added")
	}
}

func TestAADIsHonoured(t *testing.T) {
	sim := newSim(t)
	dir := enrolDir(t, sim, "node-a")
	w := configured(t, sim, dir, "node-a")

	blob, err := w.Encrypt(context.Background(), []byte("openbao root key"), wrapping.WithAad([]byte("bao")))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := w.Decrypt(context.Background(), blob); err == nil {
		t.Fatal("Decrypt succeeded without the AAD it was encrypted with")
	}
	if _, err := w.Decrypt(context.Background(), blob, wrapping.WithAad([]byte("bao"))); err != nil {
		t.Fatalf("Decrypt with matching AAD: %v", err)
	}
}

func TestLoadArtifactsRejectsDuplicateNodes(t *testing.T) {
	sim := newSim(t)
	dir := enrolDir(t, sim, "node-a")

	data, err := os.ReadFile(filepath.Join(dir, "node-a.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node-a-copy.json"), data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadArtifacts(dir); err == nil {
		t.Fatal("loadArtifacts accepted two artifacts for the same node")
	}
}

func TestLoadArtifactsRejectsUnknownVersion(t *testing.T) {
	sim := newSim(t)
	dir := enrolDir(t, sim, "node-a")

	var art envelope.Artifact
	data, _ := os.ReadFile(filepath.Join(dir, "node-a.json"))
	if err := json.Unmarshal(data, &art); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	art.Version = 99
	data, _ = json.Marshal(art)
	if err := os.WriteFile(filepath.Join(dir, "node-a.json"), data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadArtifacts(dir); err == nil {
		t.Fatal("loadArtifacts accepted an unknown artifact version")
	}
}
