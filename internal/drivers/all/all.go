/*
Package all links every read driver into a binary so that drivers.Default()
can select them. Import it for side effects in each binary that polls devices:

	import _ "github.com/beekamai/network-scheme/internal/drivers/all"
*/
package all

import (
	_ "github.com/beekamai/network-scheme/internal/drivers/generic" /* fallback, registers generic-snmp */
)
