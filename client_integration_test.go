package tsmart_test

import (
	"context"
	"testing"
	"time"

	"github.com/bswilliamson/go-tsmart"
)

func TestIntegration(t *testing.T) {
	if !integrationEnabled() {
		t.Skip("use go test -integration to include the integration tests. " +
			"This requires real devices to be available on the network.")
	}

	client := tsmart.New("255.255.255.255:1337")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	respCh, err := client.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}

	count := 0

	t.Log("listening for devices")
	for {
		select {
		case dev := <-respCh:
			count++
			t.Logf("discovered device: %+v\n", dev)
		case <-ctx.Done():
			t.Log("done")
			if count < 1 {
				t.Error("failed: no devices discovered. Are there any on the network?")
			}
			return
		}
	}
}
