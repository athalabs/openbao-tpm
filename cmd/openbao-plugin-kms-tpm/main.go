// Command openbao-plugin-kms-tpm is the OpenBao auto-unseal plugin.
//
// OpenBao runs it as a subprocess while sealed, so it takes no configuration of
// its own beyond the seal stanza:
//
//	plugin_directory = "/opt/openbao/plugins"
//
//	plugin "kms" "tpm" {
//	  command = "openbao-plugin-kms-tpm"
//	}
//
//	seal "tpm" {
//	  artifacts = "/etc/openbao/tpm"
//	  device    = "/dev/tpmrm0"
//	}
//
// The name in the seal stanza must match the name in the plugin stanza.
package main

import (
	"github.com/athalabs/openbao-tpm/internal/tpmwrap"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper { return tpmwrap.New() },
	})
}
