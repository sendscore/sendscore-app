package budget

import "testing"

func TestTakeAndRelease(t *testing.T) {
	b := New(10)
	if !b.Take(10) {
		t.Fatal("refused within the limit")
	}
	if b.Take(1) {
		t.Fatal("took past the limit")
	}
	b.Release(4)
	if !b.Take(4) || b.Take(1) {
		t.Error("a refused charge was kept, or a release was lost")
	}
}
