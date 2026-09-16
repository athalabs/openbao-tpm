package tpmwrap

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/athalabs/openbao-tpm/internal/envelope"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/plugin/v2/plugintest"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// TestServer_TPMWrapper is not a test: it is the plugin server that
// TestPluginTransport spawns, and it skips unless that harness asks for it. It
// serves exactly what cmd/openbao-plugin-kms-tpm serves.
func TestServer_TPMWrapper(t *testing.T) {
	plugintest.Server(t, &plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper { return New() },
	})
}

// TestPluginTransport exercises the wrapper the way OpenBao does: over the
// go-plugin gRPC boundary, in a separate process, configured only through the
// config map from the seal stanza.
//
// Decrypt is not covered here, since that needs the node's TPM in the plugin
// process; it is covered in-process by the other tests and on hardware.
func TestPluginTransport(t *testing.T) {
	sim := newSim(t)
	dir := enrolDir(t, sim, "node-a", "node-b")

	raw, err := plugintest.Client(t, "TestServer_TPMWrapper").Dispense("wrapper")
	if err != nil {
		t.Fatalf("dispensing wrapper: %v", err)
	}
	wrapper, ok := raw.(wrapping.Wrapper)
	if !ok {
		t.Fatalf("dispensed %T, want a wrapping.Wrapper", raw)
	}
	ctx := context.Background()

	// The plugin has no wrapper instance until it is configured; every other
	// call before SetConfig reports that.
	if _, err := wrapper.KeyId(ctx); err == nil {
		t.Fatal("KeyId succeeded before SetConfig")
	}

	config, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"artifacts": dir,
		"node":      "node-a",
	}))
	if err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	typ, err := wrapper.Type(ctx)
	if err != nil {
		t.Fatalf("Type: %v", err)
	}
	if typ != WrapperType {
		t.Fatalf("type %q, want %q", typ, WrapperType)
	}
	if got := config.Metadata["recipients"]; got != "node-a,node-b" {
		t.Fatalf("recipients %q, want \"node-a,node-b\"", got)
	}

	blob, err := wrapper.Encrypt(ctx, []byte("openbao root key"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if blob.KeyInfo == nil {
		t.Fatal("blob carries no key info")
	}

	keyID, err := wrapper.KeyId(ctx)
	if err != nil {
		t.Fatalf("KeyId: %v", err)
	}
	if blob.KeyInfo.KeyId != keyID {
		t.Fatalf("blob key ID %q != wrapper key ID %q", blob.KeyInfo.KeyId, keyID)
	}

	var recipients []envelope.Recipient
	if err := json.Unmarshal(blob.KeyInfo.WrappedKey, &recipients); err != nil {
		t.Fatalf("decoding recipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Fatalf("got %d recipients, want 2", len(recipients))
	}
}
