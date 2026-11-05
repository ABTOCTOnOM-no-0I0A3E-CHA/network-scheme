package session

import "context"

/* Check runs one round of Run's checks (limits, connections, freeze, policy). */
func (m *Manager) Check(ctx context.Context) { m.check(ctx) }

/* MgmtTargets is mgmtTargets for the tests. */
var MgmtTargets = mgmtTargets

/* SetRecoverPage sets how many session rows Recover reads at a time. */
func SetRecoverPage(n int) (restore func()) {
	old := recoverPage
	recoverPage = n
	return func() { recoverPage = old }
}
