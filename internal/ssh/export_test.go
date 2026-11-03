package ssh

import "context"

/* NotInSession is the host key callback's check against execpub.device_busy. */
func (h *HostKeys) NotInSession(ctx context.Context, fp string) error { return h.notInSession(ctx, fp) }
