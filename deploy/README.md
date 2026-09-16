# Deploying

`openbao-values.yaml` is a starting point for the openbao-helm chart, not a
finished deployment. It was derived by reading chart 0.29.4 and OpenBao v2.6.2
sources, then exercised end to end with the throwaway manifest in
`e2e-openbao.yaml`.

## TPM device access: two separate gates

Reaching the TPM from an unprivileged pod needs both. Fixing one and not the
other looks like an unexplained `permission denied`.

**1. The permission bits.** On Talos, `/dev/tpmrm0` is `root:root 0600`, and the
chart runs the server as uid 100 with `runAsNonRoot: true`. A udev rule fixes
this:

    KERNEL=="tpmrm[0-9]*", GROUP="989", MODE="0660"

with `supplementalGroups: [989]` on the pod. Two Talos specifics, both learned
the hard way:

- **The GID must be 999 or lower.** Talos has no `/etc/group`, so udev asks
  systemd to synthesize a numeric group, and systemd refuses anything above
  `SYSTEM_GID_MAX` (999). A rule with `GROUP="1000"` is dropped *in its
  entirety* — including the `MODE` — and the only trace is a udevd log line:
  `Failed to resolve group '1000', ignoring: Unknown group`. The device stays
  `root:root 0600` and nothing else reports an error.
- **The config path differs by version.** Talos 1.14 takes a separate
  `UdevRulesConfig` document and applies it live, via a controller. Talos 1.13
  takes `machine.udev.rules` and writes the rules during the boot sequence, so
  the change only takes effect **after the node reboots**. Apply with a YAML
  merge patch: `talosctl patch machineconfig` rejects JSON6902 patches on
  multi-document configs.

Do not reach for `MODE="0666"` without a group to dodge the GID limit: that lets
anything on the host drive a TPM which, on these systems, also holds the disk
encryption keys.

**2. The devices cgroup.** A `hostPath` device node is bind-mounted but not added
to the container's device allowlist, so an unprivileged container gets `EPERM` on
open regardless of the permission bits. That is what a **TPM device plugin** is
for: it makes the runtime add the device with a cgroup grant. The throwaway
manifest here sidesteps this by running privileged. Before a production
deployment, test with the device plugin, the supplemental group, uid 100, and no
privileged flag.

SELinux: the device carries `tpm_device_t`, which udev does not change. On a node
running SELinux in enforcing mode, correct permission bits may still not be
enough.

## End-to-end result

`just e2e <node>` deploys a single-node OpenBao v2.6.2 sealed by that node's TPM:

    Auto Seal: tpm (builtin: false, device: "/dev/tpmrm0",
               key_id: "…", node: "…", recipients: "…")

- `bao operator init` succeeded with the TPM seal and issued Shamir recovery
  shares.
- Deleting the pod and letting it restart: `core: unsealed with stored key`,
  `Sealed false`, with no operator input.
- Swapping in another node's artifact relabelled as this node — what an attacker
  substituting their own machine's enrollment looks like — leaves it sealed and
  looping on `envelope: no recipient for key … (this envelope was not wrapped to
  this machine)`. Restoring the real artifact unseals it again.

Two things that manifest does differently from a real deployment: the container
runs privileged as root, and the plugin binary is copied into the init container
rather than carried in its image, so it has to be re-copied after every restart.

## Other things that will bite

- **`plugin_directory` cannot be a ConfigMap or Secret mount.** Kubernetes writes
  those as symlinks into a `..data` directory; OpenBao resolves symlinks and then
  insists the binary sits directly in the plugin directory. An emptyDir filled by
  an init container is the documented pattern, and the chart has a commented
  example of exactly this shape.
- **`command` must be a bare filename.** It is joined onto `plugin_directory`, so
  an absolute path is rejected as outside it.
- **`sha256sum` is required on v2.6.2.** A missing one is only a warning at parse
  time, then the seal fails with `start plugin client: error verifying checksum:
  no checksum provided`. It becomes optional in v2.7.0, which is also the release
  that removes the built-in seals entirely.
- **`version` is documented as required but is not enforced for KMS plugins.**
- **The plugin needs a writable `/tmp`**: go-plugin puts its unix socket there.
  The chart's default is fine; `readOnlyRootFilesystem: true` without a `/tmp`
  emptyDir would break it.
- **The server image is Alpine/musl**, so the plugin must be a static binary.
  The release builds it with `CGO_ENABLED=0`.
- **Pod-level env vars override the plugin stanza's `env`**, since the host
  environment is appended after it.
- **A pod pinned with `nodeName` will not bind a `WaitForFirstConsumer` volume.**
  That bypasses the scheduler, and the claim stays `Pending` forever. Use a node
  selector.

## Verifying what you deploy

Every release publishes an image signed with cosign keyless, an SBOM attestation,
build provenance, and the plugin binary's sha256.

    cosign verify ghcr.io/athalabs/openbao-tpm@sha256:… \
      --certificate-identity-regexp '^https://github.com/athalabs/openbao-tpm/' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

    gh attestation verify --owner athalabs oci://ghcr.io/athalabs/openbao-tpm@sha256:…

Pin both the image digest and the `sha256sum` in the seal stanza. They are
independent: the digest fixes which image the init container stages, and the
sha256sum is what OpenBao checks before it will execute the plugin, so a tampered
binary fails even if it reaches the plugin directory.

## Enrollment, which is manual on purpose

1. `just probe <node>` and `openbao-tpm enroll -out /tmp/<node>.json` on each node
   that should be able to unseal.
2. Collect the artifacts into the `openbao-tpm-artifacts` Secret, one key per
   node.
3. `openbao-tpm verify -artifact <file>` on each, and optionally
   `challenge`/`activate` to confirm the machine holds the TPM you think it does.
4. Keep a backup of the artifacts. The TPM holds no copy of the private blob;
   losing the file means that node can no longer unseal, even though its TPM is
   fine.

Adding a node later means enrolling it, updating the Secret, and rotating the
root key so the stored blob is re-wrapped to the new set. `KeyId` is a digest of
the enrolled set, so OpenBao reports the drift in the meantime.
