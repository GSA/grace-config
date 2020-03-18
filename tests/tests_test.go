package tests

import (
	"testing"

	"github.com/GSA/grace-tftest/tester"
)

func TestRun(t *testing.T) {
	err := tester.Run(".", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
}
