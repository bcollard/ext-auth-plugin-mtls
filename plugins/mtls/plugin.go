package main

import (
	impl "github.com/bcollard/ext-auth-plugin-mtls/plugins/mtls/pkg"
	"github.com/solo-io/ext-auth-plugins/api"
)

func main() {}

// Compile-time assertion
var _ api.ExtAuthPlugin = new(impl.Mtls)

// This is the exported symbol that Gloo will look for.
//noinspection GoUnusedGlobalVariable
var Plugin impl.Mtls
