package recording

import (
	"context"
	"crypto/sha256"
	"time"
)

/* SetMaxChunk bounds a chunk's plaintext for a test. */
func SetMaxChunk(n int) (restore func()) {
	old := maxChunk
	maxChunk = n
	return func() { maxChunk = old }
}

/* MaxChunk is the bound of a chunk's plaintext. */
func MaxChunk() int { return maxChunk }

/* ChunkMAC and ManifestMAC are the rows' MACs: what only a holder of the key could forge. */
func (st *Store) ChunkMAC(session [16]byte, device int64, n int, ctSum, dekSum []byte) []byte {
	return st.chunkMAC(session, device, n, ctSum, dekSum)
}

/* ManifestMAC is the manifest row's MAC. */
func (st *Store) ManifestMAC(session [16]byte, device int64, chunks int, total []byte) []byte {
	return st.manifestMAC(session, device, chunks, total)
}

/*
Outputs records pieces of device output on a stream that stores nothing (they
stay below a chunk) and returns the masked asciicast events it buffered: the
masker's boundary without a database.
*/
func Outputs(clean, mask func(string) string, pieces ...string) string {
	st := &Store{c: Config{Clean: clean, Now: time.Now}}
	s := &Stream{st: st, mask: mask, start: st.c.Now(), total: sha256.New(), limit: 1 << 40}
	for _, p := range pieces {
		_ = s.Output(context.Background(), p)
	}
	s.flushCarry()
	return string(s.buf)
}

/* SetMaxAnswer bounds one recorded answer for a test. */
func SetMaxAnswer(n int) (restore func()) {
	old := maxAnswer
	maxAnswer = n
	return func() { maxAnswer = old }
}

/* ReplayBound is the most a recording under a limit of maxMiB holds. */
func ReplayBound(maxMiB int) int { return replayBound(maxMiB) }

/* Busy takes every replay slot until release. */
func (st *Store) Busy() (release func()) {
	for range cap(st.replays) {
		st.replays <- struct{}{}
	}
	return func() {
		for range cap(st.replays) {
			<-st.replays
		}
	}
}
