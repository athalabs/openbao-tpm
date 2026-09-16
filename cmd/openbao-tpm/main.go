// Command openbao-tpm is a prototype of TPM-bound key wrapping for OpenBao
// auto-unseal.
//
// It proves one property: a payload can be wrapped so that only specific,
// enrolled machines can recover it — any of them, unattended, with no secret
// stored anywhere off those machines. That is the missing piece for running
// OpenBao HA on this cluster without pinning it to a single node.
//
//	enroll    on a node: create its TPM-resident unwrap key, write the artifact
//	wrap      anywhere: encrypt a payload to one or more enrolled nodes
//	unwrap    on a node: recover the payload using that node's TPM
//	pcrs      on a node: show PCR values and the policy digest they produce
//	selftest  on a node: enroll, wrap, unwrap, and report
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/athalabs/openbao-tpm/internal/envelope"
	"github.com/athalabs/openbao-tpm/internal/tpmkey"
	"github.com/google/go-tpm/tpm2/transport"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "enroll":
		err = enroll(os.Args[2:])
	case "wrap":
		err = wrap(os.Args[2:])
	case "unwrap":
		err = unwrap(os.Args[2:])
	case "pcrs":
		err = showPCRs(os.Args[2:])
	case "selftest":
		err = selftest(os.Args[2:])
	case "policydebug":
		err = policyDebug(os.Args[2:])
	case "ek":
		err = showEK(os.Args[2:])
	case "verify":
		err = verifyArtifact(os.Args[2:])
	case "challenge":
		err = makeChallenge(os.Args[2:])
	case "activate":
		err = activate(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `openbao-tpm <command> [flags]

  enroll    create this node's TPM unwrap key and write its artifact
  wrap      encrypt a payload to one or more enrolled nodes
  unwrap    recover a payload using this node's TPM
  pcrs      print PCR values and the policy digest they produce
  selftest  enroll, wrap and unwrap on this node, then report
  policydebug  compare the policy digests a trial and a real session produce
  ek        show the endorsement key and any manufacturer certificate
  verify    check an artifact's attestation offline, against a pinned EK
  challenge build a credential-activation challenge for a node
  activate  answer a challenge on this node (proves it holds the pinned EK)

Run <command> -h for flags.
`)
}

// deviceFlag and pcrsFlag are shared by the TPM-side commands.
func deviceFlag(fs *flag.FlagSet) *string {
	return fs.String("device", tpmkey.DefaultDevice, "TPM device path")
}

func pcrsFlag(fs *flag.FlagSet, def []uint) *string {
	return fs.String("pcrs", joinPCRs(def), "comma-separated PCR indices (SHA-256 bank) to bind the policy to")
}

func joinPCRs(pcrs []uint) string {
	parts := make([]string, len(pcrs))
	for i, p := range pcrs {
		parts[i] = strconv.FormatUint(uint64(p), 10)
	}
	return strings.Join(parts, ",")
}

func parsePCRs(s string) ([]uint, error) {
	var out []uint
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		n, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad PCR %q: %w", field, err)
		}
		if n > 23 {
			return nil, fmt.Errorf("PCR %d out of range", n)
		}
		out = append(out, uint(n))
	}
	if len(out) == 0 {
		return nil, errors.New("no PCRs given")
	}
	return out, nil
}

// nodeName prefers the Kubernetes downward API, since in a pod the hostname is
// the pod name, not the node we are actually bound to.
func nodeName(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if n := os.Getenv("NODE_NAME"); n != "" {
		return n, nil
	}
	return os.Hostname()
}

func enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	device := deviceFlag(fs)
	pcrs := pcrsFlag(fs, tpmkey.DefaultPCRs())
	node := fs.String("node", "", "node name to record (default: $NODE_NAME, else hostname)")
	out := fs.String("out", "-", "write the artifact here (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	selected, err := parsePCRs(*pcrs)
	if err != nil {
		return err
	}
	name, err := nodeName(*node)
	if err != nil {
		return err
	}

	t, err := tpmkey.Open(*device)
	if err != nil {
		return err
	}
	defer t.Close()

	art, err := tpmkey.Enroll(t, name, selected)
	if err != nil {
		return err
	}
	return writeJSON(*out, art)
}

func wrap(args []string) error {
	fs := flag.NewFlagSet("wrap", flag.ExitOnError)
	var recipients stringList
	fs.Var(&recipients, "recipient", "path to an enrollment artifact; repeat for each node")
	in := fs.String("in", "-", "payload to wrap (- for stdin)")
	out := fs.String("out", "-", "write the envelope here (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(recipients) == 0 {
		return errors.New("at least one -recipient is required")
	}

	arts := make([]envelope.Artifact, 0, len(recipients))
	for _, path := range recipients {
		var art envelope.Artifact
		if err := readJSON(path, &art); err != nil {
			return err
		}
		if art.Version != envelope.ArtifactVersion {
			return fmt.Errorf("%s: artifact version %d, want %d", path, art.Version, envelope.ArtifactVersion)
		}
		arts = append(arts, art)
	}

	payload, err := readAll(*in)
	if err != nil {
		return err
	}
	env, err := envelope.Wrap(payload, nil, arts)
	if err != nil {
		return err
	}
	return writeJSON(*out, env)
}

func unwrap(args []string) error {
	fs := flag.NewFlagSet("unwrap", flag.ExitOnError)
	device := deviceFlag(fs)
	artifact := fs.String("artifact", "", "this node's enrollment artifact (required)")
	envPath := fs.String("envelope", "", "envelope to open (required)")
	out := fs.String("out", "-", "write the payload here (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *artifact == "" || *envPath == "" {
		return errors.New("-artifact and -envelope are required")
	}

	var art envelope.Artifact
	if err := readJSON(*artifact, &art); err != nil {
		return err
	}
	var env envelope.Envelope
	if err := readJSON(*envPath, &env); err != nil {
		return err
	}

	recipient, err := env.RecipientFor(art.KeyName)
	if err != nil {
		return err
	}

	t, err := tpmkey.Open(*device)
	if err != nil {
		return err
	}
	defer t.Close()

	dek, err := tpmkey.Unwrap(t, &art, recipient.WrappedDEK)
	if err != nil {
		return err
	}
	payload, err := env.Open(dek, nil)
	if err != nil {
		return err
	}
	return writeRaw(*out, payload)
}

func showPCRs(args []string) error {
	fs := flag.NewFlagSet("pcrs", flag.ExitOnError)
	device := deviceFlag(fs)
	pcrs := pcrsFlag(fs, []uint{0, 4, 7, 11})
	if err := fs.Parse(args); err != nil {
		return err
	}
	selected, err := parsePCRs(*pcrs)
	if err != nil {
		return err
	}

	t, err := tpmkey.Open(*device)
	if err != nil {
		return err
	}
	defer t.Close()

	values, err := tpmkey.ReadPCRs(t, selected)
	if err != nil {
		return err
	}
	indices := make([]int, 0, len(values))
	for pcr := range values {
		indices = append(indices, int(pcr))
	}
	sort.Ints(indices)
	for _, pcr := range indices {
		fmt.Printf("PCR %2d  %s\n", pcr, hex.EncodeToString(values[uint(pcr)]))
	}

	digest, err := tpmkey.PolicyDigest(t, selected)
	if err != nil {
		return err
	}
	fmt.Printf("policy digest for %s: %s\n", joinPCRs(selected), hex.EncodeToString(digest))
	return nil
}

// selftest is the demonstration: it enrols a throwaway key, wraps a payload to
// it, and unwraps it again, all on this node. A successful run means this
// machine can recover payloads wrapped to it with no operator input.
func selftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	device := deviceFlag(fs)
	pcrs := pcrsFlag(fs, tpmkey.DefaultPCRs())
	if err := fs.Parse(args); err != nil {
		return err
	}
	selected, err := parsePCRs(*pcrs)
	if err != nil {
		return err
	}
	name, err := nodeName("")
	if err != nil {
		return err
	}

	t, err := tpmkey.Open(*device)
	if err != nil {
		return err
	}
	defer t.Close()

	return runSelftest(t, name, selected)
}

func runSelftest(t transport.TPM, node string, pcrs []uint) error {
	fmt.Printf("node:      %s\n", node)
	fmt.Printf("pcrs:      %s\n", joinPCRs(pcrs))

	art, err := tpmkey.Enroll(t, node, pcrs)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	fmt.Printf("key name:  %s\n", art.KeyName)
	fmt.Printf("policy:    %s\n", hex.EncodeToString(art.PolicyDigest))

	payload := []byte("openbao-tpm selftest payload")
	env, err := envelope.Wrap(payload, nil, []envelope.Artifact{*art})
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}

	dek, err := tpmkey.Unwrap(t, art, env.Recipients[0].WrappedDEK)
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}
	got, err := env.Open(dek, nil)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if string(got) != string(payload) {
		return fmt.Errorf("round trip mismatch: got %q", got)
	}
	fmt.Println("result:    PASS (wrapped and unwrapped via this TPM)")
	return nil
}

// policyDebug exists because a trial policy session and a real one do not
// necessarily agree, and when they disagree the only symptom is
// TPM_RC_POLICY_FAIL at use time, long after enrollment.
func policyDebug(args []string) error {
	fs := flag.NewFlagSet("policydebug", flag.ExitOnError)
	device := deviceFlag(fs)
	pcrs := pcrsFlag(fs, tpmkey.DefaultPCRs())
	if err := fs.Parse(args); err != nil {
		return err
	}
	selected, err := parsePCRs(*pcrs)
	if err != nil {
		return err
	}

	t, err := tpmkey.Open(*device)
	if err != nil {
		return err
	}
	defer t.Close()

	pcrDigest, err := tpmkey.PCRDigest(t, selected)
	if err != nil {
		return err
	}
	fmt.Printf("pcr digest (computed here):   %s\n", hex.EncodeToString(pcrDigest))

	realDigest, err := tpmkey.PolicyDigest(t, selected)
	if err != nil {
		return err
	}
	fmt.Printf("policy digest (real session): %s\n", hex.EncodeToString(realDigest))

	trialEmpty, err := tpmkey.TrialPolicyDigest(t, selected, nil)
	if err != nil {
		return err
	}
	fmt.Printf("policy digest (trial, empty): %s  matches real: %t\n",
		hex.EncodeToString(trialEmpty), bytes.Equal(trialEmpty, realDigest))

	trialExplicit, err := tpmkey.TrialPolicyDigest(t, selected, pcrDigest)
	if err != nil {
		return err
	}
	fmt.Printf("policy digest (trial, given): %s  matches real: %t\n",
		hex.EncodeToString(trialExplicit), bytes.Equal(trialExplicit, realDigest))
	return nil
}

// showEK reports the TPM's endorsement key and whatever certificate the
// manufacturer left in NV. Without a verifiable certificate, enrolling a node is
// trust-on-first-use: we would be believing the machine's own claim about which
// TPM it has.
func showEK(args []string) error {
	fs := flag.NewFlagSet("ek", flag.ExitOnError)
	device := deviceFlag(fs)
	certOut := fs.String("cert-out", "", "write the EK certificate (DER) here if one is found")
	if err := fs.Parse(args); err != nil {
		return err
	}

	t, err := tpmkey.Open(*device)
	if err != nil {
		return err
	}
	defer t.Close()

	info, err := tpmkey.EK(t)
	if err != nil {
		return err
	}
	fmt.Printf("TPM:            manufacturer %q vendor %q firmware %s\n",
		info.Manufacturer, info.VendorString, info.Firmware)
	fmt.Printf("EK name:        %s\n", info.Name)
	fmt.Printf("EK pubkey hash: %s\n", info.PublicKeyHash)
	fmt.Println("well-known EK certificate indices, probed directly:")
	for _, probe := range info.Probed {
		fmt.Printf("  %s\n", probe)
	}
	fmt.Println("NV indices defined:")
	if len(info.NVIndices) == 0 {
		fmt.Println("  (none)")
	}
	for _, index := range info.NVIndices {
		fmt.Printf("  %s\n", index)
	}

	if info.Certificate == nil {
		fmt.Println("EK certificate: NOT PRESENT in NV")
		return nil
	}

	fmt.Printf("EK certificate: %d bytes at %s\n", len(info.Certificate), info.CertificateIndex)
	cert, err := x509.ParseCertificate(info.Certificate)
	if err != nil {
		fmt.Printf("  (could not parse as X.509: %v)\n", err)
	} else {
		fmt.Printf("  subject:      %q\n", cert.Subject.String())
		fmt.Printf("  issuer:       %q\n", cert.Issuer.String())
		fmt.Printf("  serial:       %s\n", cert.SerialNumber)
		fmt.Printf("  valid:        %s .. %s\n",
			cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("  signature:    %s\n", cert.SignatureAlgorithm)
		for _, url := range cert.IssuingCertificateURL {
			fmt.Printf("  issuer cert:  %s\n", url)
		}
		for _, url := range cert.CRLDistributionPoints {
			fmt.Printf("  CRL:          %s\n", url)
		}
	}
	if *certOut != "" {
		if err := os.WriteFile(*certOut, info.Certificate, 0o644); err != nil {
			return err
		}
		fmt.Printf("  written to:   %s\n", *certOut)
	}
	return nil
}

// verifyArtifact checks an enrollment offline. With -pin it also checks the
// artifact's EK against the one recorded for that node, which is what turns
// "some TPM" into "the TPM we enrolled".
func verifyArtifact(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	artifact := fs.String("artifact", "", "artifact to verify (required)")
	pin := fs.String("pin", "", "pinned EK file for this node, as written by -write-pin")
	writePin := fs.String("write-pin", "", "record this artifact's EK as the pin for its node")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *artifact == "" {
		return errors.New("-artifact is required")
	}

	var art envelope.Artifact
	if err := readJSON(*artifact, &art); err != nil {
		return err
	}
	if err := tpmkey.VerifyArtifact(&art); err != nil {
		return err
	}
	fmt.Println("attestation:  OK (key is non-duplicable, policy-gated, and certified by an AK)")
	fmt.Printf("node:         %s\n", art.Node)
	fmt.Printf("EK name:      %s\n", hex.EncodeToString(art.EKName))

	if *pin != "" {
		var pinned envelope.Artifact
		if err := readJSON(*pin, &pinned); err != nil {
			return err
		}
		if !bytes.Equal(pinned.EKName, art.EKName) || !bytes.Equal(pinned.EKPublic, art.EKPublic) {
			return fmt.Errorf("EK MISMATCH: %s presented a different TPM than the pinned one (%s)",
				art.Node, hex.EncodeToString(pinned.EKName))
		}
		fmt.Println("pinned EK:    matches")
		fmt.Println("note:         run `challenge` + `activate` to prove the node holds this EK,")
		fmt.Println("              rather than merely having copied its public half")
	}
	if *writePin != "" {
		pinned := tpmkey.Pin(&art)
		if err := writeJSON(*writePin, &pinned); err != nil {
			return err
		}
		fmt.Printf("pin written:  %s\n", *writePin)
	}
	return nil
}

func makeChallenge(args []string) error {
	fs := flag.NewFlagSet("challenge", flag.ExitOnError)
	artifact := fs.String("artifact", "", "artifact (or pin) holding the EK and AK to challenge (required)")
	out := fs.String("out", "-", "write the challenge here")
	expectOut := fs.String("expect-out", "", "write the expected answer here; keep it off the node")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *artifact == "" {
		return errors.New("-artifact is required")
	}

	var art envelope.Artifact
	if err := readJSON(*artifact, &art); err != nil {
		return err
	}
	challenge, err := tpmkey.NewChallenge(&art)
	if err != nil {
		return err
	}

	expected := challenge.Expected
	challenge.Expected = nil // never hand the answer to the node
	if err := writeJSON(*out, challenge); err != nil {
		return err
	}
	if *expectOut != "" {
		return writeRaw(*expectOut, []byte(hex.EncodeToString(expected)+"\n"))
	}
	fmt.Fprintf(os.Stderr, "expected answer: %s\n", hex.EncodeToString(expected))
	return nil
}

func activate(args []string) error {
	fs := flag.NewFlagSet("activate", flag.ExitOnError)
	device := deviceFlag(fs)
	challengePath := fs.String("challenge", "", "challenge to answer (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *challengePath == "" {
		return errors.New("-challenge is required")
	}

	var challenge tpmkey.Challenge
	if err := readJSON(*challengePath, &challenge); err != nil {
		return err
	}

	t, err := tpmkey.Open(*device)
	if err != nil {
		return err
	}
	defer t.Close()

	answer, err := tpmkey.Activate(t, &challenge)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(answer))
	return nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func readAll(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func readJSON(path string, v any) error {
	data, err := readAll(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeRaw(path, append(data, '\n'))
}

func writeRaw(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	// 0600: an artifact is not secret, but a payload written by `unwrap` is.
	return os.WriteFile(path, data, 0o600)
}
