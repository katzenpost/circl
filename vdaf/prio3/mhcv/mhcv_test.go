package mhcv

import (
	"testing"

	"github.com/katzenpost/circl/internal/test"
	"github.com/katzenpost/circl/vdaf/prio3/internal/flp_test"
)

func TestMhcv(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		const MaxWeight = 2
		m, err := newFlpMultiCountHotVec(5, MaxWeight, 3)
		test.CheckNoErr(t, err, "new flp failed")
		flp_test.TestInvalidQuery(t, &m.FLP)
	})
}
