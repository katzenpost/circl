package sum

import (
	"testing"

	"github.com/katzenpost/circl/internal/test"
	"github.com/katzenpost/circl/vdaf/prio3/internal/flp_test"
)

func TestSum(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		const MaxMeas = 4
		s, err := newFlpSum(MaxMeas)
		test.CheckNoErr(t, err, "new flp failed")
		flp_test.TestInvalidQuery(t, &s.FLP)
	})
}
