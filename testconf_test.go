package tsmart_test

import (
	"flag"
	"testing"
)

var integration = flag.Bool("integration", false, "enable integration tests")

func TestMain(m *testing.M) {
	flag.Parse()
	m.Run()
}

func integrationEnabled() bool {
	return *integration
}
