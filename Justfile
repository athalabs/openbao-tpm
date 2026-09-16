default:
  @just --list

# The TPM simulator used by the tpmkey tests is cgo + OpenSSL.
export CGO_CFLAGS := "-I/opt/homebrew/opt/openssl@3/include"
export CGO_LDFLAGS := "-L/opt/homebrew/opt/openssl@3/lib"

test:
  go test ./... -race

lint:
  go vet ./...
  gofmt -l .

# The nodes are amd64; these binaries run in a pod on one of them.
build:
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/openbao-tpm-linux-amd64 ./cmd/openbao-tpm

build-plugin:
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/openbao-plugin-kms-tpm ./cmd/openbao-plugin-kms-tpm

# OpenBao checks this against the plugin stanza's sha256sum.
plugin-sha: build-plugin
  @shasum -a 256 bin/openbao-plugin-kms-tpm | cut -d" " -f1

# Put the probe pod on a node and copy the binary in. NODE must have SecureBoot
# and a TPM.
probe NODE: build
  sed 's/NODE_PLACEHOLDER/{{NODE}}/' deploy/tpm-probe.yaml | kubectl apply -f -
  kubectl -n tpm-probe wait --for=condition=Ready pod/tpm-probe-{{NODE}} --timeout=120s
  kubectl -n tpm-probe cp bin/openbao-tpm-linux-amd64 tpm-probe-{{NODE}}:/tmp/openbao-tpm
  kubectl -n tpm-probe exec tpm-probe-{{NODE}} -- chmod +x /tmp/openbao-tpm

# Run the end-to-end demonstration in the probe pod.
selftest NODE:
  kubectl -n tpm-probe exec tpm-probe-{{NODE}} -- /tmp/openbao-tpm selftest

policydebug NODE:
  kubectl -n tpm-probe exec tpm-probe-{{NODE}} -- /tmp/openbao-tpm policydebug

pcrs NODE:
  kubectl -n tpm-probe exec tpm-probe-{{NODE}} -- /tmp/openbao-tpm pcrs

clean-probe:
  kubectl delete namespace tpm-probe --ignore-not-found

# End-to-end: a real OpenBao on NODE that unseals itself with this node's TPM.
# Enrol NODE first (just probe NODE, then enroll) -- see deploy/README.md.
e2e NODE: build-plugin
  sed -e "s/NODE_PLACEHOLDER/{{NODE}}/" -e "s/PLUGIN_SHA/$(shasum -a 256 bin/openbao-plugin-kms-tpm | cut -d' ' -f1)/" deploy/e2e-openbao.yaml | kubectl apply -f -
  kubectl -n tpm-probe wait --for=condition=Initialized=false pod -l app.kubernetes.io/name=openbao-tpm-e2e --timeout=60s || true
  kubectl -n tpm-probe cp bin/openbao-plugin-kms-tpm $(kubectl -n tpm-probe get pod -l app.kubernetes.io/name=openbao-tpm-e2e -o name | head -1 | cut -d/ -f2):/openbao/plugins/openbao-plugin-kms-tpm -c stage-plugin
  kubectl -n tpm-probe rollout status deploy/openbao --timeout=180s

e2e-status:
  kubectl -n tpm-probe exec deploy/openbao -- bao status || true
