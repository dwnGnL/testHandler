package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHttpHeader_SetInt(t *testing.T) {
	tests := []struct {
		name string
		val  int
		want string
	}{
		{"10", 10, "10"},
		{"10", 268, "268"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := fmt.Sprint(tt.val)
			assert.Equal(t, tt.want, w)
		})
	}
}
