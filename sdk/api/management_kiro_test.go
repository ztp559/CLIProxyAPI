package api

import (
	"reflect"
	"testing"
)

func TestManagementTokenRequesterIncludesKiro(t *testing.T) {
	t.Parallel()

	requester := NewManagementTokenRequester(nil, nil)
	method := reflect.ValueOf(requester).MethodByName("RequestKiroToken")
	if !method.IsValid() {
		t.Fatal("ManagementTokenRequester does not expose RequestKiroToken")
	}
}
