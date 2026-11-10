package changeset

/* WaitDryRun waits for the dry-run of changeset id started in this process (none: returns at once). */
func (m *Manager) WaitDryRun(id string) {
	cid, _ := ParseID(id)
	m.mu.Lock()
	d := m.dry[cid]
	m.mu.Unlock()
	if d != nil {
		<-d.done
	}
}
