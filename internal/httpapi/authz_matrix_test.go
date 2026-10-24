package httpapi_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/*
subjects in the order the matrix exercises them; anon has no session. The
"A" subjects hold their role on group A only; requests target objects in
group A (foreignMatrix repeats the group-scoped routes against group B).
*/
var subjectNames = []string{"anon", "viewer", "viewerA", "operator", "operatorA", "auditor", "admin", "adminA"}

/* scopedSubjects are the group-bound subjects of foreignMatrix. */
var scopedSubjects = []string{"viewerA", "operatorA", "adminA"}

/* matrix: method+pattern -> expected status for each subject. */
var matrix = map[string]map[string]int{
	"GET /api/health":              {"anon": 200, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 200, "admin": 200, "adminA": 200},
	"POST /api/auth/login":         {"anon": 200, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 200, "admin": 200, "adminA": 200},
	"POST /api/auth/totp":          {"anon": 204, "viewer": 204, "viewerA": 204, "operator": 204, "operatorA": 204, "auditor": 204, "admin": 204, "adminA": 204},
	"POST /api/auth/enroll":        {"anon": 200, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 200, "admin": 200, "adminA": 200},
	"POST /api/auth/stepup":        {"anon": 401, "viewer": 204, "viewerA": 204, "operator": 204, "operatorA": 204, "auditor": 204, "admin": 204, "adminA": 204},
	"POST /api/auth/logout":        {"anon": 401, "viewer": 204, "viewerA": 204, "operator": 204, "operatorA": 204, "auditor": 204, "admin": 204, "adminA": 204},
	"GET /api/auth/me":             {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 200, "admin": 200, "adminA": 200},
	"GET /api/users":               {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 403},
	"POST /api/users":              {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 403},
	"PATCH /api/users/{id}":        {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"GET /api/users/{id}/bindings": {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 403},
	"PUT /api/users/{id}/bindings": {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"GET /api/groups":              {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 403},
	"POST /api/groups":             {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 403},
	"PATCH /api/groups/{id}":       {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"DELETE /api/groups/{id}":      {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"GET /api/audit":               {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 200, "admin": 200, "adminA": 403},

	"GET /api/devices":                                        {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/devices":                                       {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 201},
	"GET /api/devices/{id}":                                   {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"PATCH /api/devices/{id}":                                 {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"DELETE /api/devices/{id}":                                {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"GET /api/devices/{id}/profiles":                          {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"PUT /api/devices/{id}/profiles/{kind}":                   {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"DELETE /api/devices/{id}/profiles/{kind}":                {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"POST /api/devices/{id}/poll":                             {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 202, "operatorA": 202, "auditor": 403, "admin": 202, "adminA": 202},
	"GET /api/devices/{id}/interfaces":                        {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/arp":                               {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/mac":                               {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/vlans":                             {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/lldp":                              {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/entities":                          {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/routes":                            {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/metrics/if":                        {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/backups":                           {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/backups/diff":                      {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/backups/{vid}":                     {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/backups/{vid}/download":            {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/devices/{id}/backup-state":                      {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/devices/{id}/backups":                          {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 202, "operatorA": 202, "auditor": 403, "admin": 202, "adminA": 202},
	"GET /api/discovery/scans":                                {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/discovery/scans":                               {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 201},
	"PATCH /api/discovery/scans/{id}":                         {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"PUT /api/discovery/scans/{id}/profile":                   {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"GET /api/discovery/inbox":                                {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/discovery/inbox/{id}/accept":                   {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 201},
	"POST /api/discovery/inbox/{id}/ignore":                   {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"GET /api/events":                                         {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/events/unidentified":                            {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/trap-rules":                                     {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 403},
	"POST /api/trap-rules":                                    {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 403},
	"DELETE /api/trap-rules/{id}":                             {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"GET /api/ws":                                             {"anon": 401, "viewer": 426, "viewerA": 426, "operator": 426, "operatorA": 426, "auditor": 403, "admin": 426, "adminA": 426},
	"GET /api/problems":                                       {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/problems/{id}":                                  {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/problems/{id}/ack":                             {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 204, "operatorA": 204, "auditor": 403, "admin": 204, "adminA": 204},
	"GET /api/templates":                                      {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/templates":                                     {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 201},
	"PATCH /api/templates/{id}":                               {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"DELETE /api/templates/{id}":                              {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"GET /api/templates/{id}/triggers":                        {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/templates/{id}/triggers":                       {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 201},
	"PATCH /api/templates/{id}/triggers/{trigger_id}":         {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"DELETE /api/templates/{id}/triggers/{trigger_id}":        {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"GET /api/devices/{id}/trigger-overrides":                 {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 200},
	"PUT /api/devices/{id}/trigger-overrides/{trigger_id}":    {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"DELETE /api/devices/{id}/trigger-overrides/{trigger_id}": {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"GET /api/maintenance":                                    {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/maintenance":                                   {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 201},
	"DELETE /api/maintenance/{id}":                            {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 204},
	"GET /api/system/status":                                  {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 200, "operatorA": 403, "auditor": 403, "admin": 200, "adminA": 403},
	"GET /api/topology":                                       {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"GET /api/topology/changes":                               {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/links":                                         {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 403},
	"DELETE /api/links/{id}":                                  {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"GET /api/map/views":                                      {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/map/views":                                     {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 403},
	"PATCH /api/map/views/{id}":                               {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"DELETE /api/map/views/{id}":                              {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"GET /api/map/views/{id}/areas":                           {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"POST /api/map/views/{id}/areas":                          {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 403},
	"PATCH /api/map/views/{id}/areas/{area_id}":               {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"DELETE /api/map/views/{id}/areas/{area_id}":              {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"PUT /api/map/views/{id}/positions":                       {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
	"POST /api/map/backgrounds":                               {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 201, "adminA": 403},
	"GET /api/map/backgrounds/{id}":                           {"anon": 401, "viewer": 200, "viewerA": 200, "operator": 200, "operatorA": 200, "auditor": 403, "admin": 200, "adminA": 200},
	"DELETE /api/map/backgrounds/{id}":                        {"anon": 401, "viewer": 403, "viewerA": 403, "operator": 403, "operatorA": 403, "auditor": 403, "admin": 204, "adminA": 403},
}

/*
foreignMatrix: every group-scoped route requested by the group-A subjects
against objects (or a target group) in group B. A subject that holds the
permission somewhere gets 404, never 403, for a foreign object; lists answer
200 without the foreign rows.
*/
var foreignMatrix = map[string]map[string]int{
	"GET /api/devices":                                        {"viewerA": 200, "operatorA": 200, "adminA": 200},
	"POST /api/devices":                                       {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"GET /api/devices/{id}":                                   {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"PATCH /api/devices/{id}":                                 {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"DELETE /api/devices/{id}":                                {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"GET /api/devices/{id}/profiles":                          {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"PUT /api/devices/{id}/profiles/{kind}":                   {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"DELETE /api/devices/{id}/profiles/{kind}":                {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"POST /api/devices/{id}/poll":                             {"viewerA": 403, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/interfaces":                        {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/arp":                               {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/mac":                               {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/vlans":                             {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/lldp":                              {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/entities":                          {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/routes":                            {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/metrics/if":                        {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/backups":                           {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/backups/diff":                      {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/backups/{vid}":                     {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/backups/{vid}/download":            {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/devices/{id}/backup-state":                      {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"POST /api/devices/{id}/backups":                          {"viewerA": 403, "operatorA": 404, "adminA": 404},
	"GET /api/discovery/scans":                                {"viewerA": 403, "operatorA": 403, "adminA": 200},
	"POST /api/discovery/scans":                               {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"PATCH /api/discovery/scans/{id}":                         {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"PUT /api/discovery/scans/{id}/profile":                   {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"GET /api/discovery/inbox":                                {"viewerA": 403, "operatorA": 403, "adminA": 200},
	"POST /api/discovery/inbox/{id}/accept":                   {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"POST /api/discovery/inbox/{id}/ignore":                   {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"GET /api/events":                                         {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/events/unidentified":                            {"viewerA": 200, "operatorA": 200, "adminA": 200},
	"GET /api/problems":                                       {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/problems/{id}":                                  {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"POST /api/problems/{id}/ack":                             {"viewerA": 403, "operatorA": 404, "adminA": 404},
	"GET /api/templates":                                      {"viewerA": 403, "operatorA": 403, "adminA": 200},
	"POST /api/templates":                                     {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"PATCH /api/templates/{id}":                               {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"DELETE /api/templates/{id}":                              {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"GET /api/templates/{id}/triggers":                        {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"POST /api/templates/{id}/triggers":                       {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"PATCH /api/templates/{id}/triggers/{trigger_id}":         {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"DELETE /api/templates/{id}/triggers/{trigger_id}":        {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"GET /api/devices/{id}/trigger-overrides":                 {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"PUT /api/devices/{id}/trigger-overrides/{trigger_id}":    {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"DELETE /api/devices/{id}/trigger-overrides/{trigger_id}": {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"GET /api/maintenance":                                    {"viewerA": 403, "operatorA": 403, "adminA": 200},
	"POST /api/maintenance":                                   {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"DELETE /api/maintenance/{id}":                            {"viewerA": 403, "operatorA": 403, "adminA": 404},
	"GET /api/ws":                                             {"viewerA": 426, "operatorA": 426, "adminA": 426},
	"GET /api/topology":                                       {"viewerA": 404, "operatorA": 404, "adminA": 404},
	"GET /api/topology/changes":                               {"viewerA": 200, "operatorA": 200, "adminA": 200},
	"GET /api/map/views":                                      {"viewerA": 200, "operatorA": 200, "adminA": 200},
	"GET /api/map/views/{id}/areas":                           {"viewerA": 200, "operatorA": 200, "adminA": 200},
	"GET /api/map/backgrounds/{id}":                           {"viewerA": 200, "operatorA": 200, "adminA": 200},
}

/* subject is a logged-in user (nil for anon) whose session holds a fresh step-up. */
type subject struct {
	uid          int64
	sec          string
	cookie, csrf string
}

/* authed adds the subject's cookie and CSRF token to r. */
func (s *subject) authed(r req) req {
	if s != nil {
		r.cookie, r.csrf = s.cookie, s.csrf
	}
	return r
}

/* matrixEnv is a fixture with one subject per role and a spare user for login routes. */
type matrixEnv struct {
	*fixture
	subjects    map[string]*subject
	spare       string   /* enrolled user without bindings, logged in by the login routes */
	spareBackup []string /* its unused backup codes */
	groupA      int64    /* the group of the "A" subjects and of the matrix targets */
	groupB      int64    /* a group no "A" subject is bound to */
	target      int64    /* group the next validRequest targets */
}

func (f *fixture) bind(uid int64, bs ...rbac.Binding) {
	f.t.Helper()
	ctx := context.Background()
	st := rbac.NewStore(f.env.Pool("nms_api"))
	if err := pgx.BeginFunc(ctx, f.env.Pool("nms_api"), func(tx pgx.Tx) error {
		return st.SetBindings(ctx, tx, uid, bs)
	}); err != nil {
		f.t.Fatalf("bind %d: %v", uid, err)
	}
}

/* login creates a user with bindings bs and logs it in; stepUp also refreshes the step-up. */
func (f *fixture) login(stepUp bool, bs ...rbac.Binding) *subject {
	f.t.Helper()
	name := uniqueName("subj")
	s := &subject{uid: f.createUser(name)}
	f.bind(s.uid, bs...)
	s.sec, s.cookie = f.enroll(name)
	s.csrf = f.me(s.cookie).CSRFToken
	if stepUp {
		f.stepUp(s)
	}
	return s
}

/* stepUp moves the clock to a new TOTP step and steps the session up. */
func (f *fixture) stepUp(s *subject) {
	f.t.Helper()
	f.clk.Advance(30 * time.Second)
	resp := f.do(s.authed(req{method: "POST", path: "/api/auth/stepup", body: map[string]string{"code": totpCode(f.t, s.sec, f.clk.Now())}}))
	if resp.StatusCode != http.StatusNoContent {
		f.t.Fatalf("stepup status %d", resp.StatusCode)
	}
	s.cookie, _ = sessionCookie(f.t, resp)
}

func newMatrixEnv(t *testing.T) *matrixEnv {
	t.Helper()
	m := &matrixEnv{fixture: newFixture(t, nil), subjects: map[string]*subject{"anon": nil}}
	m.groupA, m.groupB = m.newGroup(), m.newGroup()
	m.target = m.groupA
	for _, n := range subjectNames[1:] {
		b := rbac.Binding{Role: rbac.Role(strings.TrimSuffix(n, "A"))}
		if strings.HasSuffix(n, "A") {
			b.GroupID = &m.groupA
		}
		m.subjects[n] = m.login(false, b)
	}
	/* One clock step for all: each user has its own TOTP replay counter. */
	m.clk.Advance(30 * time.Second)
	for _, n := range subjectNames[1:] {
		s := m.subjects[n]
		resp := m.do(s.authed(req{method: "POST", path: "/api/auth/stepup", body: map[string]string{"code": totpCode(t, s.sec, m.clk.Now())}}))
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s stepup status %d", n, resp.StatusCode)
		}
		s.cookie, _ = sessionCookie(t, resp)
	}
	m.spare = uniqueName("spare")
	m.createUser(m.spare)
	_, _, m.spareBackup = m.enrollCodes(m.spare)
	return m
}

func (m *matrixEnv) group() int64 {
	m.t.Helper()
	ctx := context.Background()
	var id int64
	if err := pgx.BeginFunc(ctx, m.env.Pool("nms_api"), func(tx pgx.Tx) error {
		var err error
		id, err = rbac.NewStore(m.env.Pool("nms_api")).CreateGroup(ctx, tx, nil, uniqueName("grp"))
		return err
	}); err != nil {
		m.t.Fatal(err)
	}
	return id
}

func (m *matrixEnv) loginSpare() string {
	m.t.Helper()
	resp := m.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": m.spare, "password": goodPW}})
	lr := decode[loginResp](m.t, resp)
	if lr.Stage != "totp" {
		m.t.Fatalf("spare login = %+v", lr)
	}
	return lr.Challenge
}

/*
validRequest builds a request for route key that is valid in every respect
except authorization, with fresh targets so that every subject's request
could succeed on its own.
*/
func (m *matrixEnv) validRequest(key string, s *subject) req {
	m.t.Helper()
	switch key {
	case "GET /api/health":
		return req{method: "GET", path: "/api/health"}
	case "POST /api/auth/login":
		return req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": m.spare, "password": goodPW}}
	case "POST /api/auth/totp":
		code := m.spareBackup[0]
		m.spareBackup = m.spareBackup[1:]
		return req{method: "POST", path: "/api/auth/totp", body: map[string]string{"challenge": m.loginSpare(), "code": code}}
	case "POST /api/auth/enroll":
		name := uniqueName("enr")
		m.createUser(name)
		lr := decode[loginResp](m.t, m.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": name, "password": goodPW}}))
		u, err := url.Parse(lr.OTPAuthURI)
		if err != nil {
			m.t.Fatal(err)
		}
		return req{method: "POST", path: "/api/auth/enroll", body: map[string]string{
			"challenge": lr.Challenge, "code": totpCode(m.t, u.Query().Get("secret"), m.clk.Now()),
		}}
	case "POST /api/auth/stepup":
		code := "000000"
		if s != nil {
			m.clk.Advance(30 * time.Second)
			code = totpCode(m.t, s.sec, m.clk.Now())
		}
		return req{method: "POST", path: "/api/auth/stepup", body: map[string]string{"code": code}}
	case "POST /api/auth/logout":
		return req{method: "POST", path: "/api/auth/logout"}
	case "GET /api/auth/me":
		return req{method: "GET", path: "/api/auth/me"}
	case "GET /api/users":
		return req{method: "GET", path: "/api/users"}
	case "POST /api/users":
		return req{method: "POST", path: "/api/users", body: map[string]string{"username": uniqueName("new"), "password": goodPW}}
	case "PATCH /api/users/{id}":
		return req{method: "PATCH", path: fmt.Sprintf("/api/users/%d", m.createUser(uniqueName("tgt"))), body: map[string]bool{"disabled": true}}
	case "GET /api/users/{id}/bindings":
		return req{method: "GET", path: fmt.Sprintf("/api/users/%d/bindings", m.subjects["viewer"].uid)}
	case "PUT /api/users/{id}/bindings":
		return req{method: "PUT", path: fmt.Sprintf("/api/users/%d/bindings", m.createUser(uniqueName("tgt"))),
			body: []map[string]any{{"role": "viewer", "group_id": nil}, {"role": "operator", "group_id": m.group()}}}
	case "GET /api/groups":
		return req{method: "GET", path: "/api/groups"}
	case "POST /api/groups":
		return req{method: "POST", path: "/api/groups", body: map[string]any{"name": uniqueName("g"), "parent_id": m.group()}}
	case "PATCH /api/groups/{id}":
		return req{method: "PATCH", path: fmt.Sprintf("/api/groups/%d", m.group()), body: map[string]any{"name": uniqueName("r"), "parent_id": nil}}
	case "DELETE /api/groups/{id}":
		return req{method: "DELETE", path: fmt.Sprintf("/api/groups/%d", m.group())}
	case "GET /api/audit":
		return req{method: "GET", path: "/api/audit?limit=5"}
	}
	if r, ok := m.deviceRequest(key); ok {
		return r
	}
	if r, ok := m.backupRequest(key); ok {
		return r
	}
	if r, ok := m.eventRequest(key); ok {
		return r
	}
	if r, ok := m.monitoringRequest(key); ok {
		return r
	}
	if r, ok := m.mapRequest(key); ok {
		return r
	}
	m.t.Fatalf("no valid request for %s", key)
	return req{}
}

/* deviceRequest builds valid requests for the device and discovery routes with targets in m.target. */
func (m *matrixEnv) deviceRequest(key string) (req, bool) {
	g := m.target
	ct := base64.StdEncoding.EncodeToString([]byte("sealed-credential"))
	dev := func(format string) string { return fmt.Sprintf(format, m.newDevice(g)) }
	switch key {
	case "GET /api/devices":
		return req{method: "GET", path: "/api/devices"}, true
	case "POST /api/devices":
		return req{method: "POST", path: "/api/devices", body: map[string]any{"name": uniqueName("d"), "address": nextAddr().String(), "group_id": g}}, true
	case "GET /api/devices/{id}":
		return req{method: "GET", path: dev("/api/devices/%d")}, true
	case "PATCH /api/devices/{id}":
		return req{method: "PATCH", path: dev("/api/devices/%d"), body: map[string]any{"name": uniqueName("r"), "interval_avail_s": 60}}, true
	case "DELETE /api/devices/{id}":
		return req{method: "DELETE", path: dev("/api/devices/%d")}, true
	case "GET /api/devices/{id}/profiles":
		return req{method: "GET", path: dev("/api/devices/%d/profiles")}, true
	case "PUT /api/devices/{id}/profiles/{kind}":
		return req{method: "PUT", path: dev("/api/devices/%d/profiles/snmp3"), body: map[string]any{"ciphertext": ct, "key_version": 1}}, true
	case "DELETE /api/devices/{id}/profiles/{kind}":
		id := m.newDevice(g)
		m.newProfile(devices.Owner{Kind: devices.OwnerDevice, ID: id}, "ssh_read")
		return req{method: "DELETE", path: fmt.Sprintf("/api/devices/%d/profiles/ssh_read", id)}, true
	case "POST /api/devices/{id}/poll":
		return req{method: "POST", path: dev("/api/devices/%d/poll")}, true
	case "GET /api/devices/{id}/interfaces", "GET /api/devices/{id}/arp", "GET /api/devices/{id}/mac", "GET /api/devices/{id}/vlans",
		"GET /api/devices/{id}/lldp", "GET /api/devices/{id}/entities", "GET /api/devices/{id}/routes":
		return req{method: "GET", path: dev("/api/devices/%d/" + strings.TrimPrefix(key, "GET /api/devices/{id}/") + "?limit=10")}, true
	case "GET /api/devices/{id}/metrics/if":
		to := time.Now().UTC()
		q := url.Values{"if_index": {"1"}, "from": {to.Add(-time.Hour).Format(time.RFC3339)}, "to": {to.Format(time.RFC3339)}}
		return req{method: "GET", path: dev("/api/devices/%d/metrics/if") + "?" + q.Encode()}, true
	case "GET /api/discovery/scans":
		return req{method: "GET", path: "/api/discovery/scans"}, true
	case "POST /api/discovery/scans":
		return req{method: "POST", path: "/api/discovery/scans", body: map[string]any{"cidr": "192.0.2.0/24", "group_id": g, "interval_s": 3600}}, true
	case "PATCH /api/discovery/scans/{id}":
		return req{method: "PATCH", path: fmt.Sprintf("/api/discovery/scans/%d", m.newScan(g)), body: map[string]any{"enabled": false}}, true
	case "PUT /api/discovery/scans/{id}/profile":
		return req{method: "PUT", path: fmt.Sprintf("/api/discovery/scans/%d/profile", m.newScan(g)),
			body: map[string]any{"kind": "snmp3", "ciphertext": ct, "key_version": 1}}, true
	case "GET /api/discovery/inbox":
		return req{method: "GET", path: "/api/discovery/inbox"}, true
	case "POST /api/discovery/inbox/{id}/accept":
		return req{method: "POST", path: fmt.Sprintf("/api/discovery/inbox/%d/accept", m.newDiscovered(g)),
			body: map[string]any{"name": uniqueName("acc"), "group_id": g}}, true
	case "POST /api/discovery/inbox/{id}/ignore":
		return req{method: "POST", path: fmt.Sprintf("/api/discovery/inbox/%d/ignore", m.newDiscovered(g))}, true
	}
	return req{}, false
}

func routeKeys() []string {
	var keys []string
	for _, r := range httpapi.Routes() {
		keys = append(keys, r.Method+" "+r.Pattern)
	}
	return keys
}

func TestEveryRouteInMatrix(t *testing.T) {
	keys := routeKeys()
	for _, k := range keys {
		row, ok := matrix[k]
		if !ok {
			t.Errorf("route %s has no matrix row", k)
			continue
		}
		for _, n := range subjectNames {
			if _, ok := row[n]; !ok {
				t.Errorf("matrix row %s lacks subject %s", k, n)
			}
		}
		if len(row) != len(subjectNames) {
			t.Errorf("matrix row %s has unknown subjects: %v", k, row)
		}
	}
	for k := range matrix {
		if !slices.Contains(keys, k) {
			t.Errorf("matrix row %s matches no registered route", k)
		}
	}
	for _, r := range httpapi.Routes() {
		k := r.Method + " " + r.Pattern
		row, ok := foreignMatrix[k]
		if r.Policy.Scoped != ok {
			t.Errorf("route %s: scoped=%v but foreign matrix row present=%v", k, r.Policy.Scoped, ok)
		}
		if ok && len(row) != len(scopedSubjects) {
			t.Errorf("foreign matrix row %s: %v", k, row)
		}
	}
	for k := range foreignMatrix {
		if !slices.Contains(keys, k) {
			t.Errorf("foreign matrix row %s matches no registered route", k)
		}
	}
}

/* TestAuthzMatrixForeign runs every group-scoped route as the group-A subjects against group B. */
func TestAuthzMatrixForeign(t *testing.T) {
	m := newMatrixEnv(t)
	m.target = m.groupB
	for k, row := range foreignMatrix {
		for _, n := range scopedSubjects {
			s := m.subjects[n]
			resp := m.do(s.authed(m.validRequest(k, s)))
			want := row[n]
			switch want {
			case http.StatusNotFound:
				wantError(t, resp, want, "not_found")
			case http.StatusForbidden:
				wantError(t, resp, want, "forbidden")
			default:
				if resp.StatusCode != want {
					t.Errorf("%s as %s on group B: status %d, want %d", k, n, resp.StatusCode, want)
				}
			}
		}
	}
}

func TestAuthzMatrix(t *testing.T) {
	m := newMatrixEnv(t)
	keys := routeKeys()
	/* Logout ends the sessions the other rows need, so it runs last. */
	keys = append(slices.DeleteFunc(keys, func(k string) bool { return k == "POST /api/auth/logout" }), "POST /api/auth/logout")
	for i, k := range keys {
		for _, n := range subjectNames {
			s := m.subjects[n]
			/* Each route is asked from a client address of its own: the whole matrix would exceed the per-IP limit of 600 requests a minute. */
			rq := m.validRequest(k, s)
			rq.remote, rq.xff = "10.0.0.1:40000", fmt.Sprintf("192.0.%d.%d", 100+i/250, i%250+1)
			resp := m.do(s.authed(rq))
			want := matrix[k][n]
			if resp.StatusCode != want {
				b, _ := io.ReadAll(resp.Body)
				t.Errorf("%s as %s: status %d, want %d; body %s", k, n, resp.StatusCode, want, b)
				continue
			}
			switch want {
			case http.StatusUnauthorized:
				wantError(t, resp, want, "unauthenticated")
			case http.StatusForbidden:
				wantError(t, resp, want, "forbidden")
			}
			if k == "POST /api/auth/stepup" && want == http.StatusNoContent {
				s.cookie, _ = sessionCookie(t, resp)
			}
		}
	}
}

func TestStepUpEnforced(t *testing.T) {
	m := newMatrixEnv(t)
	/* A fresh login has no step-up. */
	admin := m.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	n := 0
	for _, r := range httpapi.Routes() {
		if !r.Policy.StepUp {
			continue
		}
		n++
		k := r.Method + " " + r.Pattern
		wantError(t, m.do(admin.authed(m.validRequest(k, admin))), http.StatusForbidden, "stepup_required")
	}
	if n == 0 {
		t.Fatal("no step-up routes registered")
	}
	/* Step-up lapses after 5 minutes. */
	m.stepUp(admin)
	m.clk.Advance(5*time.Minute + time.Second)
	wantError(t, m.do(admin.authed(m.validRequest("POST /api/users", admin))), http.StatusForbidden, "stepup_required")
}

func TestRBACLoadErrorIs500(t *testing.T) {
	var d httpapi.Deps
	f := newFixture(t, func(dd *httpapi.Deps) { d = *dd })
	s := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	/* Sessions still resolve, but loading the role bindings fails. */
	broken, err := pgxpool.NewWithConfig(context.Background(), d.Pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	d.RBAC = rbac.NewStore(broken)
	f.h = httpapi.NewRouter(d)
	wantError(t, f.do(s.authed(req{method: "GET", path: "/api/users"})), http.StatusInternalServerError, "internal")
}

/* eventRequest builds valid requests for the event, trap rule and system routes; events are asked for a device in m.target. */
func (m *matrixEnv) eventRequest(key string) (req, bool) {
	switch key {
	case "GET /api/events":
		return req{method: "GET", path: fmt.Sprintf("/api/events?device_id=%d", m.newDevice(m.target))}, true
	case "GET /api/events/unidentified":
		return req{method: "GET", path: "/api/events/unidentified"}, true
	case "GET /api/trap-rules":
		return req{method: "GET", path: "/api/trap-rules"}, true
	case "POST /api/trap-rules":
		return req{method: "POST", path: "/api/trap-rules", body: map[string]string{"trap_oid": m.newOID(), "name": uniqueName("rule"), "severity": "high"}}, true
	case "DELETE /api/trap-rules/{id}":
		var id int64
		if err := m.env.Pool("postgres").QueryRow(context.Background(),
			`INSERT INTO events.trap_rule (trap_oid, name, severity) VALUES ($1, 'x', 'info') RETURNING id`, m.newOID()).Scan(&id); err != nil {
			m.t.Fatal(err)
		}
		return req{method: "DELETE", path: fmt.Sprintf("/api/trap-rules/%d", id)}, true
	case "GET /api/system/status":
		return req{method: "GET", path: "/api/system/status"}, true
	case "GET /api/ws": /* a recorder cannot upgrade: admitted callers reach the handshake and are told to upgrade */
		return req{method: "GET", path: "/api/ws", origin: publicOrigin}, true
	}
	return req{}, false
}

/* newOID returns an unused OID under a private enterprise arc. */
func (f *fixture) newOID() string { return fmt.Sprintf("1.3.6.1.4.1.99999.%d", seq.Add(1)) }
