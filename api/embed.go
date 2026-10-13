// Package api holds the OpenAPI specification, embedded into the binary.
package api

import _ "embed"

//go:embed openapi.yaml
var OpenAPISpec []byte
