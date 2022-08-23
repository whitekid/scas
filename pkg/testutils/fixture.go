package testutils

import (
	"context"
	"os"

	"scas/pkg/helper"
)

func CopyFixtures(ctx context.Context, dest, src string) {
	Must(os.RemoveAll(dest))
	Must(os.MkdirAll(dest, 0755))
	Must(helper.Execute("cp", "-Rp", src, dest).Do(ctx))
}
