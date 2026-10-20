/*
Package deploy embeds the deployment templates and the files that
nmsctl install writes next to the rendered compose project.
*/
package deploy

import "embed"

/*
FS holds templates/*.tmpl (rendered by internal/install), the postgres
init script that creates the service roles and schemas, and the systemd
units of the hourly audit anchor.
*/
//go:embed templates/*.tmpl postgres/initdb/10-roles.sh systemd/*
var FS embed.FS
