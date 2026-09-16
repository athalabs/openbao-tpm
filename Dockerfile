# Carries the binaries for the init container that stages the seal plugin into
# OpenBao's plugin_directory. It is not a runtime image: nothing here is the
# process OpenBao talks to. OpenBao runs the plugin binary itself, out of an
# emptyDir, and verifies its sha256 against the seal config.
#
# Binaries are built outside and copied in, so the hash published with the
# release is the hash of exactly these files.
#
# busybox, not distroless: the init container needs a shell to copy the binary
# and write the node name.
FROM busybox:1.37.0-musl

ARG PLUGIN_SHA256
ARG VERSION
LABEL org.opencontainers.image.source="https://github.com/athalabs/openbao-tpm" \
      org.opencontainers.image.description="TPM-bound auto-unseal for OpenBao" \
      org.opencontainers.image.licenses="MPL-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      io.atha.openbao-tpm.plugin-sha256="${PLUGIN_SHA256}"

COPY dist/openbao-plugin-kms-tpm /usr/local/bin/openbao-plugin-kms-tpm
COPY dist/openbao-tpm /usr/local/bin/openbao-tpm

# The sha256 that must appear in OpenBao's plugin stanza, readable without
# pulling the binary apart:
#   docker run --rm <image> cat /plugin.sha256
COPY dist/plugin.sha256 /plugin.sha256
