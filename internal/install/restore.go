package install

import (
	"context"
	"fmt"
	"io"
	"path"
)

/*
PrepareRestoredHost does install's host steps for an install directory that
nmsctl restore has put back, before any container exists: nmsctl in
HostBinary, the egress rules of the devices network (checked to be on
Docker's forwarding path) and the Docker drop-in that applies them at every
Docker start. root is Options.Root (tests only).
*/
func PrepareRestoredHost(ctx context.Context, sys System, root string, out io.Writer) error {
	o := Options{Out: out, Root: root}
	if err := installHostBinary(o, sys); err != nil {
		return err
	}
	e, err := LoadEgress(o.hostPath(path.Join(o.paths().Etc, EgressFile)))
	if err != nil {
		return err
	}
	if err := ApplyEgress(ctx, sys, e); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if err := CheckDockerUsesEgress(ctx, sys); err != nil {
		return err
	}
	return installEgressDropIn(ctx, o, sys)
}

/* FinishRestoredHost enables the hourly audit anchor timer and writes the installed marker. */
func FinishRestoredHost(ctx context.Context, sys System, root string, out io.Writer) error {
	o := Options{Out: out, Root: root}
	if err := installUnits(ctx, o, sys); err != nil {
		return err
	}
	return writeExcl(o.markerPath(), nil, 0o644)
}
