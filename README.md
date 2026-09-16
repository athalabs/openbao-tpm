# openbao-tpm

TPM-bound auto-unseal for OpenBao: the root key can only be recovered on
specific, enrolled machines, with no operator present and no unseal key stored
anywhere off those machines.

Built for bare-metal Kubernetes on Talos Linux with SecureBoot and firmware
TPMs, but nothing here is specific to that.

## Why

OpenBao needs some KMS to unwrap its root key at startup, or a human types
Shamir shares after every restart. Putting that key in a Kubernetes Secret, in
SOPS, or at a cloud KMS just moves the problem. A TPM can hold it instead.

The property this provides, which nothing off the shelf does today:

> A payload is wrapped so that **only specific enrolled machines** can recover
> it — any one of them, unattended — and no machine outside that set can, even
> holding every file involved.

The second half matters for HA. A key created inside a TPM cannot be exported,
so wrapping to one node pins OpenBao to that node. Here the envelope carries
**one wrapped DEK per enrolled node**, so the pod can be scheduled on any of them
and still unseal itself.

Existing work stops short of this: OpenBao has no TPM seal (openbao#1200 is open),
go-kms-wrapping#145 adds a single-TPM wrapper, and salrashid123/go-tpm-wrapping
implements the per-node primitive. None of them fan out to several TPMs.

## How it works

1. `enroll` runs on a node and creates an RSA-2048/OAEP decryption key inside its
   TPM, under a deterministic ECC storage root key.
   - `FixedTPM | FixedParent | SensitiveDataOrigin`: the private half is
     generated in the TPM and can never leave it.
   - `UserWithAuth` off, so the only way to authorise use is a policy session.
     With it on, an empty password would work and the PCR policy would be
     decorative.
   - `NoDA`, so a crash-looping pod cannot trip the dictionary-attack lockout.
   - Policy is `PolicyPCR` over PCR 7 (SHA-256 bank).
   - It writes an *artifact*: public key, TPM-wrapped private blob (useless on
     any other machine), PCR selection, policy digest, and attestation evidence.
2. `wrap` runs anywhere, with no TPM: generate a DEK, AES-256-GCM the payload,
   wrap the DEK to each enrolled node's public key.
3. `unwrap` runs on a node: load its key under the SRK, satisfy the PCR policy,
   have the TPM decrypt its own DEK entry, open the payload.

The OpenBao seal plugin is the same three steps behind the `go-kms-wrapping`
`Wrapper` interface: `Encrypt` wraps to every enrolled node, `Decrypt` uses the
local TPM, and `KeyId` is a digest of the enrolled set so OpenBao notices when
that set drifts from what a stored blob was wrapped to.

## Enrollment is manual, by design

An operator runs `enroll` on each node through an authenticated path and commits
the resulting artifact. Provenance comes from the act itself: you watched the
artifact come off that machine's TPM.

That is also why there is no EK pinning machinery here. A pin would record "this
node's TPM is this EK" so a later artifact could be checked against it, which
matters when nodes enrol *themselves*. With manual enrollment the operator
already knows, and an attacker who could slip a foreign artifact into the set
would need repository access — at which point they can change the pod spec too.
The EK and its attestation are still recorded in every artifact, so the check can
be added later without re-enrolling anything.

`verify` and `challenge`/`activate` remain as operator tools: `verify` checks an
artifact's own attestation offline, and a challenge proves a machine really holds
the TPM you think it does.

## Commands

    openbao-tpm enroll      # on a node: create its key, write the artifact
    openbao-tpm wrap        # anywhere: encrypt a payload to enrolled nodes
    openbao-tpm unwrap      # on a node: recover a payload via its TPM
    openbao-tpm verify      # offline: check an artifact's attestation
    openbao-tpm challenge   # offline: build a credential-activation challenge
    openbao-tpm activate    # on a node: answer a challenge
    openbao-tpm pcrs        # on a node: PCR values and policy digest
    openbao-tpm policydebug # on a node: trial vs real policy digests
    openbao-tpm selftest    # on a node: enroll, wrap, unwrap, report

## OpenBao configuration

    plugin_directory = "/openbao/plugins"

    plugin "kms" "tpm" {
      command   = "openbao-plugin-kms-tpm"
      sha256sum = "…"            # published with each release
    }

    seal "tpm" {
      artifacts = "/etc/openbao/tpm"
      device    = "/dev/tpmrm0"
      node      = ""             # else $NODE_NAME, else the contents of node_file
      node_file = ""
    }

The name in the seal stanza must match the name in the plugin stanza. KMS
plugins can only be declared in the config file, never registered over the API,
because they have to work while sealed.

See [deploy/README.md](deploy/README.md) for the Kubernetes side.

## Running it

Locally, against the Microsoft reference TPM simulator:

    just test

The simulator is cgo and needs OpenSSL headers; the `Justfile` points at
Homebrew's `openssl@3`. Tests skip rather than fail if it cannot start.

On a node:

    just probe <node>      # privileged pod pinned to that node, binary copied in
    just pcrs <node>
    just selftest <node>
    just clean-probe

## What hardware showed

Verified on bare-metal Talos nodes with SecureBoot and Intel PTT firmware TPMs
(`INTC`), running two different Talos releases.

- An envelope wrapped to two nodes opens on both. That is the failover property.
- An envelope wrapped only to one is refused on the other: no recipient entry.
- **A node holding another node's artifact and envelope gets
  `TPM_RC_INTEGRITY`** — the TPM will not load a private blob sealed to another
  TPM's seed. The machine binding, demonstrated rather than asserted.
- A challenge built for one node's EK cannot be answered by another
  (`TPM_RC_VALUE`).
- A real OpenBao initialised with this seal, then restarted, came back with
  `core: unsealed with stored key` and no operator input. Substituting a foreign
  artifact leaves it sealed, looping on `envelope: no recipient for key …`.

### The trial-session bug

Enrollment originally derived the policy digest from a *trial* session without
telling it what the PCRs hash to. On Intel PTT that folds an empty digest into
the policy, so the key ends up bound to a policy no real session can satisfy:
`TPM_RC_POLICY_FAIL` at first decrypt. The TPM simulator does not reproduce it —
there, trial-with-nothing agrees with a real session — so the tests passed while
the hardware refused. `policydebug` shows all three digests side by side.
Enrollment now uses a real policy session.

### PCR 7 does not identify a machine

Measured across two nodes running different Talos versions: PCR 0, 2, 3, 6 and 7
identical; 1, 4, 5, 9 and 11 differ.

PCR 7 being identical is expected for images built by the public Talos Image
Factory: it attests "SecureBoot on, image signed by the factory key" and nothing
installation-specific, because that signing key is shared by every factory user.
It is a good choice for *stability* — a Talos upgrade does not move it — and
useless as an identity. Identity comes from the key living in that TPM. PCR 11
differs between Talos versions, which is why binding it would mean re-sealing on
every upgrade. Enrolling your own SecureBoot keys and building your own UKIs is
what would make PCR 7 yours.

### There is no EK certificate on Intel PTT

Both nodes tested report no NV indices at all, and every well-known EK
certificate index returns `TPM_RC_HANDLE`. The TPM properties read fine through
the same `GetCapability` path, so the empty NV list is real. This is normal for
firmware TPMs: they generally do not ship a certificate in NV, and Intel serves
them from an online service instead. So there is no offline proof that an EK
belongs to genuine Intel silicon — only that it belongs to a TPM, and to the same
TPM across enrollments.

### Transient object limits

A TPM guarantees room for only three transient objects, and the SRK stays loaded
throughout enrollment. Holding the EK, the AK and the unwrap key at once returns
`TPM_RC_OBJECT_MEMORY` on both PTT and the simulator, so objects are flushed as
soon as they are no longer needed.

## Not yet proven

Everything measured so far happened within a single boot.

- **Reboot persistence.** The deterministic SRK must re-derive identically after
  a restart, and PCR 7 must return to the same value.
- **Talos upgrade survival.** PCR 7 should not move across an upgrade, since the
  factory signing certificate is unchanged. Worth confirming on the next one.

## Still missing

- Somewhere to keep the artifacts. The private blob exists *only* in the artifact
  file; the TPM keeps no copy. Lose it and the envelope is unrecoverable even on
  the right machine. A per-node Kubernetes Secret, backed up like other cluster
  state.
- Recovery keys: `bao operator init` issues Shamir recovery keys even with
  auto-unseal. Split them and hold them offline.
- Device access without a privileged pod: see deploy/README.md.
- Encrypted TPM sessions. Salted, parameter-encrypted sessions matter less on a
  firmware TPM, where there is no bus to sniff, but they should be there.

## Non-goals

- Not a general secrets tool: it wraps one payload for one purpose.
- Not for nodes without SecureBoot and a TPM.
- Bootstrap secrets stay outside OpenBao. Anything needed to start it cannot live
  inside it.
