// Package tpmwrap implements the OpenBao auto-unseal interface on top of the
// per-node TPM envelope.
//
// OpenBao asks a seal to encrypt its root key at init and at rotation, and to
// decrypt it at every startup. Encryption is public-key work over the enrolled
// nodes' artifacts, so it can run anywhere. Decryption runs on the node, in the
// TPM, and only succeeds on a machine the payload was wrapped to.
package tpmwrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/athalabs/openbao-tpm/internal/envelope"
	"github.com/athalabs/openbao-tpm/internal/tpmkey"
	"github.com/google/go-tpm/tpm2/transport"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// WrapperType is the seal type, as named in OpenBao's seal stanza.
const WrapperType = wrapping.WrapperType("tpm")

// Wrapper is the seal. It holds the enrolled artifacts and knows which of them
// belongs to the node it is running on.
type Wrapper struct {
	mu sync.RWMutex

	// recipients are every enrolled node, in a stable order so the key ID is
	// reproducible.
	recipients []envelope.Artifact
	// self is this node's artifact, the only one that can decrypt.
	self *envelope.Artifact

	device string
	node   string

	// open exists so tests can substitute a TPM simulator.
	open func(device string) (transport.TPMCloser, error)
}

// New returns an unconfigured Wrapper. OpenBao calls SetConfig before use.
func New() *Wrapper {
	return &Wrapper{open: tpmkey.Open}
}

// Type implements wrapping.Wrapper.
func (w *Wrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return WrapperType, nil
}

// SetConfig loads the enrolled artifacts named by the seal stanza:
//
//	seal "tpm" {
//	  artifacts = "/etc/openbao/tpm"
//	  device    = "/dev/tpmrm0"
//	  node      = ""            # else $NODE_NAME, else the contents of node_file
//	  node_file = ""
//	}
//
// node_file exists for the Helm chart, whose extraEnvironmentVars takes only
// literal values, so NODE_NAME cannot come from the downward API there. An init
// container we do control writes the node name to a shared file instead.
//
// It fails if this node has no artifact, rather than starting and failing later
// at unseal time with a less obvious error.
func (w *Wrapper) SetConfig(_ context.Context, opts ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	options, err := wrapping.GetOpts(opts...)
	if err != nil {
		return nil, err
	}
	config := options.WithConfigMap

	dir := firstNonEmpty(config["artifacts"], os.Getenv("BAO_TPM_ARTIFACTS"))
	if dir == "" {
		return nil, fmt.Errorf("tpmwrap: no artifacts directory configured")
	}
	device := firstNonEmpty(config["device"], os.Getenv("BAO_TPM_DEVICE"), tpmkey.DefaultDevice)
	node, err := nodeName(config)
	if err != nil {
		return nil, err
	}

	recipients, err := loadArtifacts(dir)
	if err != nil {
		return nil, err
	}

	var self *envelope.Artifact
	for i := range recipients {
		if recipients[i].Node == node {
			self = &recipients[i]
			break
		}
	}
	if self == nil {
		return nil, fmt.Errorf("tpmwrap: no artifact for node %q in %s: this node cannot unseal", node, dir)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.recipients, w.self, w.device, w.node = recipients, self, device, node

	return &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"node":       node,
			"device":     device,
			"recipients": strings.Join(nodeNames(recipients), ","),
			"key_id":     keyID(recipients),
		},
	}, nil
}

// KeyId identifies the set of nodes the seal currently wraps to. OpenBao
// compares it against the ID stored with the blob, which surfaces a drifted
// enrollment set instead of leaving it to be discovered at the next failover.
func (w *Wrapper) KeyId(context.Context) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.recipients) == 0 {
		return "", fmt.Errorf("tpmwrap: not configured")
	}
	return keyID(w.recipients), nil
}

// Encrypt wraps the payload to every enrolled node.
func (w *Wrapper) Encrypt(_ context.Context, plaintext []byte, opts ...wrapping.Option) (*wrapping.BlobInfo, error) {
	options, err := wrapping.GetOpts(opts...)
	if err != nil {
		return nil, err
	}

	w.mu.RLock()
	recipients := w.recipients
	w.mu.RUnlock()
	if len(recipients) == 0 {
		return nil, fmt.Errorf("tpmwrap: not configured")
	}

	env, err := envelope.Wrap(plaintext, options.WithAad, recipients)
	if err != nil {
		return nil, err
	}
	wrappedKeys, err := json.Marshal(env.Recipients)
	if err != nil {
		return nil, fmt.Errorf("tpmwrap: encoding recipients: %w", err)
	}

	// BlobInfo has room for a single wrapped key, so the per-node list rides
	// in that field as an opaque blob.
	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Nonce,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      keyID(recipients),
			WrappedKey: wrappedKeys,
		},
	}, nil
}

// Decrypt recovers the payload using this node's TPM.
func (w *Wrapper) Decrypt(_ context.Context, blob *wrapping.BlobInfo, opts ...wrapping.Option) ([]byte, error) {
	options, err := wrapping.GetOpts(opts...)
	if err != nil {
		return nil, err
	}
	if blob == nil || blob.KeyInfo == nil {
		return nil, fmt.Errorf("tpmwrap: blob has no key information")
	}

	w.mu.RLock()
	self, device := w.self, w.device
	w.mu.RUnlock()
	if self == nil {
		return nil, fmt.Errorf("tpmwrap: not configured")
	}

	var recipients []envelope.Recipient
	if err := json.Unmarshal(blob.KeyInfo.WrappedKey, &recipients); err != nil {
		return nil, fmt.Errorf("tpmwrap: decoding recipients: %w", err)
	}
	env := &envelope.Envelope{
		Version:    envelope.EnvelopeVersion,
		Nonce:      blob.Iv,
		Ciphertext: blob.Ciphertext,
		Recipients: recipients,
	}

	recipient, err := env.RecipientFor(self.KeyName)
	if err != nil {
		return nil, err
	}

	tpm, err := w.open(device)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	dek, err := tpmkey.Unwrap(tpm, self, recipient.WrappedDEK)
	if err != nil {
		return nil, err
	}
	return env.Open(dek, options.WithAad)
}

// nodeName resolves which node this is: explicit config, then the environment,
// then a file written by an init container.
func nodeName(config map[string]string) (string, error) {
	if node := firstNonEmpty(config["node"], os.Getenv("NODE_NAME")); node != "" {
		return node, nil
	}
	path := firstNonEmpty(config["node_file"], os.Getenv("BAO_TPM_NODE_FILE"))
	if path == "" {
		return "", fmt.Errorf("tpmwrap: node name not configured: set node, NODE_NAME or node_file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("tpmwrap: reading node name from %s: %w", path, err)
	}
	node := strings.TrimSpace(string(data))
	if node == "" {
		return "", fmt.Errorf("tpmwrap: %s is empty", path)
	}
	return node, nil
}

// loadArtifacts reads every *.json in dir as an enrollment artifact.
func loadArtifacts(dir string) ([]envelope.Artifact, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("tpmwrap: reading %s: %w", dir, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("tpmwrap: no artifacts in %s", dir)
	}

	seen := make(map[string]string, len(paths))
	artifacts := make([]envelope.Artifact, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("tpmwrap: reading %s: %w", path, err)
		}
		var art envelope.Artifact
		if err := json.Unmarshal(data, &art); err != nil {
			return nil, fmt.Errorf("tpmwrap: parsing %s: %w", path, err)
		}
		if art.Version != envelope.ArtifactVersion {
			return nil, fmt.Errorf("tpmwrap: %s has artifact version %d, want %d", path, art.Version, envelope.ArtifactVersion)
		}
		if art.Node == "" || art.KeyName == "" {
			return nil, fmt.Errorf("tpmwrap: %s names no node or key", path)
		}
		if other, dup := seen[art.Node]; dup {
			return nil, fmt.Errorf("tpmwrap: %s and %s both enrol node %q", other, path, art.Node)
		}
		seen[art.Node] = path
		artifacts = append(artifacts, art)
	}

	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Node < artifacts[j].Node })
	return artifacts, nil
}

// keyID is a digest over the enrolled key names: stable for a given set of
// nodes, different as soon as one is added or re-enrolled.
func keyID(artifacts []envelope.Artifact) string {
	h := sha256.New()
	for _, art := range artifacts {
		h.Write([]byte(art.KeyName))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func nodeNames(artifacts []envelope.Artifact) []string {
	names := make([]string, len(artifacts))
	for i, art := range artifacts {
		names[i] = art.Node
	}
	return names
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
