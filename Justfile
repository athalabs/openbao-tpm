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

# The nodes are amd64; this binary runs in a pod on one of them.
build:
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/openbao-tpm-linux-amd64 ./cmd/openbao-tpm

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
