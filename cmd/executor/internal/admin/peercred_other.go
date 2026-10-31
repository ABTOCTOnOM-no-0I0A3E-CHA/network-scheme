//go:build !linux

package admin

import (
	"errors"
	"net"
)

/* peerUID cannot tell the peer outside Linux (development builds only): every connection is refused. */
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("SO_PEERCRED is available on Linux only")
}
