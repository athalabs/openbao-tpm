package tpmkey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"

	"github.com/athalabs/openbao-tpm/internal/envelope"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// akTemplate is an attestation key: a restricted signing key. Restricted means
// the TPM will only sign structures it produced itself, so a signature from it
// is a statement by the TPM rather than something an application asked it to
// rubber-stamp.
var akTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgRSA,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		Restricted:          true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
		Scheme: tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
		KeyBits: 2048,
	}),
}

// ekPolicy satisfies the standard endorsement key authorisation policy, which is
// PolicySecret against the endorsement hierarchy.
func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	_, err := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}.Execute(t)
	return err
}

// CreateAK creates the attestation key under the owner hierarchy.
func createAK(t transport.TPM) (*tpm2.CreatePrimaryResponse, func(), error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(akTemplate),
	}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("tpmkey: creating AK: %w", err)
	}
	return rsp, func() {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)
	}, nil
}

// certifyUnwrapKey has the AK sign a statement about the unwrap key: its name,
// and the attributes that make it non-duplicable. A verifier that trusts the AK
// therefore learns the unwrap key is TPM-resident without trusting the node's
// own claim about it.
func certifyUnwrapKey(t transport.TPM, ak *tpm2.CreatePrimaryResponse, object tpm2.NamedHandle) (attest, signature []byte, err error) {
	rsp, err := tpm2.Certify{
		// ADMIN role, and the key has AdminWithPolicy clear with an empty
		// auth value, so a password session is the right authorisation.
		ObjectHandle: tpm2.AuthHandle{
			Handle: object.Handle,
			Name:   object.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		SignHandle: tpm2.AuthHandle{
			Handle: ak.ObjectHandle,
			Name:   ak.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("tpmkey: certifying unwrap key: %w", err)
	}

	sig, err := rsp.Signature.Signature.RSASSA()
	if err != nil {
		return nil, nil, fmt.Errorf("tpmkey: reading certify signature: %w", err)
	}
	return rsp.CertifyInfo.Bytes(), sig.Sig.Buffer, nil
}

// Challenge is a credential-activation challenge: a secret encrypted to a
// specific TPM's EK, and bound to a specific AK name. Only a TPM holding that EK
// *and* that AK can recover the secret.
type Challenge struct {
	Node string `json:"node"`
	// CredentialBlob and Secret are the two halves the TPM needs.
	CredentialBlob []byte `json:"credential_blob"`
	Secret         []byte `json:"secret"`
	// Expected is what the node must return. It stays with the verifier.
	Expected []byte `json:"expected,omitempty"`
}

// NewChallenge builds a challenge from an artifact, on a machine with no TPM.
//
// This is what makes enrollment verifiable rather than trust-on-first-use: the
// node can only answer if it really holds the EK we pinned for it.
func NewChallenge(art *envelope.Artifact) (*Challenge, error) {
	if len(art.EKPublic) == 0 || len(art.AKName) == 0 {
		return nil, fmt.Errorf("tpmkey: artifact for %s has no EK or AK to challenge", art.Node)
	}
	ekPub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](art.EKPublic)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: parsing artifact EK: %w", err)
	}
	contents, err := ekPub.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: reading artifact EK public area: %w", err)
	}
	key, err := tpm2.ImportEncapsulationKey(contents)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: importing EK as encapsulation key: %w", err)
	}

	expected := make([]byte, 32)
	if _, err := rand.Read(expected); err != nil {
		return nil, fmt.Errorf("tpmkey: generating challenge secret: %w", err)
	}

	blob, secret, err := tpm2.CreateCredential(rand.Reader, key, art.AKName, expected)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: creating credential: %w", err)
	}
	return &Challenge{
		Node:           art.Node,
		CredentialBlob: blob,
		Secret:         secret,
		Expected:       expected,
	}, nil
}

// Pin is the identity half of an artifact: the EK that names the TPM and the AK
// that lives in it, with no unwrap key. It is what an operator records once per
// node and later challenges or compares a fresh enrollment against.
func Pin(art *envelope.Artifact) envelope.Artifact {
	return envelope.Artifact{
		Version:  art.Version,
		Node:     art.Node,
		EKPublic: art.EKPublic,
		EKName:   art.EKName,
		AKPublic: art.AKPublic,
		AKName:   art.AKName,
	}
}

// Activate answers a challenge. It runs on the node and needs both the EK and
// the AK, which is the whole point: only that TPM can produce the answer.
func Activate(t transport.TPM, challenge *Challenge) ([]byte, error) {
	ek, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: creating EK: %w", err)
	}
	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: ek.ObjectHandle}.Execute(t)
	}()

	ak, flushAK, err := createAK(t)
	if err != nil {
		return nil, err
	}
	defer flushAK()

	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{
			Handle: ak.ObjectHandle,
			Name:   ak.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: ek.ObjectHandle,
			Name:   ek.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: challenge.CredentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: challenge.Secret},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: activating credential: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}

// VerifyArtifact checks an artifact's own evidence, with no TPM and no network.
//
// It answers: is the unwrap key non-duplicable, is it gated by the policy the
// artifact claims, and did an attestation key vouch for it? What it cannot
// answer alone is whether that AK lives in the TPM we mean — for that, issue a
// Challenge and have the node activate it.
func VerifyArtifact(art *envelope.Artifact) error {
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](art.Public)
	if err != nil {
		return fmt.Errorf("verify: parsing public area: %w", err)
	}
	pub, err := public.Contents()
	if err != nil {
		return fmt.Errorf("verify: reading public area: %w", err)
	}

	switch {
	case !pub.ObjectAttributes.FixedTPM:
		return fmt.Errorf("verify: unwrap key is not FixedTPM — it could be duplicated to another TPM")
	case !pub.ObjectAttributes.FixedParent:
		return fmt.Errorf("verify: unwrap key is not FixedParent")
	case !pub.ObjectAttributes.SensitiveDataOrigin:
		return fmt.Errorf("verify: unwrap key was imported, not generated in the TPM")
	case pub.ObjectAttributes.UserWithAuth:
		return fmt.Errorf("verify: unwrap key has UserWithAuth set — its PCR policy can be bypassed with a password")
	case !pub.ObjectAttributes.Decrypt:
		return fmt.Errorf("verify: unwrap key is not a decryption key")
	}

	if got, want := hex.EncodeToString(pub.AuthPolicy.Buffer), hex.EncodeToString(art.PCRDigest); got != want {
		return fmt.Errorf("verify: key policy %s does not match the artifact's recorded PCR policy %s", got, want)
	}

	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return fmt.Errorf("verify: computing key name: %w", err)
	}
	if hex.EncodeToString(name.Buffer) != art.KeyName {
		return fmt.Errorf("verify: key name does not match the artifact's public area")
	}

	if len(art.CertifyInfo) == 0 {
		return fmt.Errorf("verify: artifact carries no attestation (enrolled with an older version?)")
	}
	return verifyCertify(art, name.Buffer)
}

// verifyCertify checks the AK's signature over the certify structure, and that
// the structure names the unwrap key.
func verifyCertify(art *envelope.Artifact, keyName []byte) error {
	akPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](art.AKPublic)
	if err != nil {
		return fmt.Errorf("verify: parsing AK public area: %w", err)
	}
	akPub, err := akPublic.Contents()
	if err != nil {
		return fmt.Errorf("verify: reading AK public area: %w", err)
	}
	if !akPub.ObjectAttributes.Restricted || !akPub.ObjectAttributes.SignEncrypt {
		return fmt.Errorf("verify: AK is not a restricted signing key, so its signature proves nothing about what it signed")
	}
	akName, err := tpm2.ObjectName(akPub)
	if err != nil {
		return fmt.Errorf("verify: computing AK name: %w", err)
	}
	if hex.EncodeToString(akName.Buffer) != hex.EncodeToString(art.AKName) {
		return fmt.Errorf("verify: AK name does not match the AK public area")
	}

	rsaAK, err := rsaPublicKey(akPub)
	if err != nil {
		return fmt.Errorf("verify: reading AK public key: %w", err)
	}

	digest := sha256Sum(art.CertifyInfo)
	if err := rsa.VerifyPKCS1v15(rsaAK, crypto.SHA256, digest, art.CertifySignature); err != nil {
		return fmt.Errorf("verify: AK signature over the attestation is invalid: %w", err)
	}

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](art.CertifyInfo)
	if err != nil {
		return fmt.Errorf("verify: parsing attestation: %w", err)
	}
	if attest.Type != tpm2.TPMSTAttestCertify {
		return fmt.Errorf("verify: attestation is of type %v, want certify", attest.Type)
	}
	certified, err := attest.Attested.Certify()
	if err != nil {
		return fmt.Errorf("verify: reading certify attestation: %w", err)
	}
	if hex.EncodeToString(certified.Name.Buffer) != hex.EncodeToString(keyName) {
		return fmt.Errorf("verify: the attestation certifies a different key than the artifact's")
	}
	return nil
}

// attachEvidence records the TPM's own statements about the freshly created
// unwrap key: the endorsement key that identifies this TPM, and an attestation
// key's signature over the unwrap key's name and attributes.
//
// Objects are flushed as soon as they are no longer needed. A TPM guarantees
// room for only three transient objects, and the SRK stays loaded throughout, so
// holding the EK, the AK and the unwrap key at the same time overflows it —
// Intel PTT and the simulator both answer TPM_RC_OBJECT_MEMORY.
func attachEvidence(t transport.TPM, art *envelope.Artifact, parent *tpm2.CreatePrimaryResponse, created *tpm2.CreateResponse) error {
	ek, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("tpmkey: creating EK: %w", err)
	}
	art.EKPublic = tpm2.Marshal(ek.OutPublic)
	art.EKName = ek.Name.Buffer
	// Flush now: the EK is only needed for its public half here.
	if _, err := (tpm2.FlushContext{FlushHandle: ek.ObjectHandle}).Execute(t); err != nil {
		return fmt.Errorf("tpmkey: flushing EK: %w", err)
	}

	loaded, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InPrivate:    created.OutPrivate,
		InPublic:     created.OutPublic,
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("tpmkey: loading unwrap key to certify it: %w", err)
	}
	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(t)
	}()

	ak, flushAK, err := createAK(t)
	if err != nil {
		return err
	}
	defer flushAK()
	art.AKPublic = tpm2.Marshal(ak.OutPublic)
	art.AKName = ak.Name.Buffer

	attest, signature, err := certifyUnwrapKey(t, ak,
		tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name})
	if err != nil {
		return err
	}
	art.CertifyInfo = attest
	art.CertifySignature = signature
	return nil
}
