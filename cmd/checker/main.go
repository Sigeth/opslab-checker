// Command checker is the built-in checker: it evaluates the check declared on
// each task of a challenge package. See pkg/sdk for the contract.
package main

import (
	"github.com/Sigeth/opslab-checker/internal/checks"
	"github.com/Sigeth/opslab-checker/pkg/sdk"
)

func main() {
	sdk.Main(checks.Builtin)
}
