package p0

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type assertions struct {
	failures []Failure
}

func (a *assertions) expect(name string, ok bool, want, got any) {
	if !ok {
		a.failures = append(a.failures, Failure{
			Name: name, Message: fmt.Sprintf("expected %v, got %v", want, got),
		})
	}
}

func (a *assertions) code(name string, want codes.Code, err error) bool {
	got := status.Code(err)
	a.expect(name, got == want, want, fmt.Sprintf("%s (%v)", got, err))
	return got == want
}

func randomProject() string {
	var id [12]byte
	rand.Read(id[:])
	return "projects/p0-" + hex.EncodeToString(id[:])
}

func validCreateTime(ts *timestamppb.Timestamp) bool {
	return ts != nil && ts.IsValid() && (ts.GetSeconds() != 0 || ts.GetNanos() != 0) && !ts.AsTime().IsZero()
}

func checkConcurrentCreate(a *assertions, create func() error) {
	var wg sync.WaitGroup
	var results [8]codes.Code
	for i := range results {
		wg.Go(func() {
			results[i] = status.Code(create())
		})
	}
	wg.Wait()
	a.expect("create_concurrent_duplicate",
		slices.Contains(results[:], codes.OK) && countCode(results[:], codes.AlreadyExists) == len(results)-1,
		"one OK and seven AlreadyExists", results)
}

func countCode(results []codes.Code, code codes.Code) int {
	count := 0
	for _, result := range results {
		if result == code {
			count++
		}
	}
	return count
}

type namedResource interface{ GetName() string }

func resourceNames[T namedResource](items []T) []string {
	names := make([]string, len(items))
	for i, item := range items {
		names[i] = item.GetName()
	}
	return names
}

type listPage struct {
	names []string
	next  string
	total *int32
}

type listResources func(parent string, size int32, token string) (listPage, error)

func (a *assertions) page(label string, page listPage, want []string, hasNext bool, total int) {
	a.expect(label+"_names", slices.Equal(page.names, want), want, page.names)
	a.expect(label+"_has_next_token", (page.next != "") == hasNext, hasNext, page.next != "")
	if page.total != nil {
		a.expect(label+"_total_size", int(*page.total) == total, total, *page.total)
	}
}

// checkPagination checks the precise contents of each page, including order and isolation.
func checkPagination(a *assertions, list listResources, parent, invalidParent string, want []string) {
	token := ""
	for start := 0; start < len(want); start += 2 {
		label := fmt.Sprintf("list_page_%d", start/2+1)
		page, err := list(parent, 2, token)
		if !a.code(label, codes.OK, err) {
			break
		}
		end := min(start+2, len(want))
		a.page(label, page, want[start:end], end < len(want), len(want))
		token = page.next
		if token == "" {
			break
		}
	}

	for _, tc := range []struct {
		label, parent, token string
		size                 int32
		code                 codes.Code
	}{
		{"list_default_page_size", parent, "", 0, codes.OK},
		{"list_oversize_accepted", parent, "", 1001, codes.OK},
		{"list_negative_page_size", parent, "", -1, codes.InvalidArgument},
		{"list_invalid_token", parent, "arbitrary token!", 2, codes.InvalidArgument},
		{"list_invalid_parent", invalidParent, "", 2, codes.InvalidArgument},
	} {
		page, err := list(tc.parent, tc.size, tc.token)
		if a.code(tc.label, tc.code, err) && tc.code == codes.OK {
			a.page(tc.label, page, want, false, len(want))
		}
	}
}

// More than 1000 resources are needed to distinguish the cap from an uncapped
// page. Keep these fixtures in their own parent so the five-resource walk above
// still exercises the final short page.
func checkPageLimits(ctx context.Context, a *assertions, list listResources, parent string, create func(id string) (string, error)) {
	want := make([]string, 1001)
	for i := range want {
		if err := ctx.Err(); err != nil {
			a.code("seed_page_limits", codes.OK, err)
			return
		}
		name, err := create(fmt.Sprintf("limit-%04d", i))
		if !a.code("seed_page_limits", codes.OK, err) {
			return
		}
		want[i] = name
	}
	for _, tc := range []struct {
		label string
		size  int32
		count int
	}{
		{"list_default_limit", 0, 100},
		{"list_at_maximum", 1000, 1000},
		{"list_above_maximum", 1001, 1000},
	} {
		page, err := list(parent, tc.size, "")
		if a.code(tc.label, codes.OK, err) {
			a.page(tc.label, page, want[:tc.count], true, len(want))
		}
	}
}
