package gost28147imit_test

import (
	"testing"

	"github.com/bigbes/gostcrypto/gost28147imit"
)

// TestIMIT_RejectsEmpty: an empty message would return the key-independent
// 0x00000000 IV state, which is a forgeable non-MAC; IMIT must panic instead.
func TestIMIT_RejectsEmpty(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)

	for _, msg := range [][]byte{nil, {}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("IMIT(key, %v): expected panic on empty message", msg)
				}
			}()

			gost28147imit.IMIT(key, msg)
		}()
	}
}
