package p0

import (
	"context"
	"slices"
	"strings"
	"time"

	pb "cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func checkTasksQueues(ctx context.Context, conn grpc.ClientConnInterface) []Failure {
	client := pb.NewCloudTasksClient(conn)
	var a assertions
	project := randomProject()
	parent := project + "/locations/us-east1"
	otherLocation := project + "/locations/us-west1"
	otherProject := randomProject() + "/locations/us-east1"
	const collection = "/queues/"
	create := func(parent string, queue *pb.Queue) (*pb.Queue, error) {
		return client.CreateQueue(ctx, &pb.CreateQueueRequest{Parent: parent, Queue: queue})
	}
	get := func(name string) (*pb.Queue, error) {
		return client.GetQueue(ctx, &pb.GetQueueRequest{Name: name})
	}
	remove := func(name string) (*emptypb.Empty, error) {
		return client.DeleteQueue(ctx, &pb.DeleteQueueRequest{Name: name})
	}

	var names []string
	var first *pb.Queue
	for _, id := range []string{"Z", "a", "A-2", "Middle", "0"} {
		queue := &pb.Queue{Name: parent + collection + id}
		names = append(names, queue.GetName())
		if id == "Z" {
			queue.State = pb.Queue_PAUSED
			queue.RateLimits = &pb.RateLimits{
				MaxDispatchesPerSecond:  7.5,
				MaxBurstSize:            13,
				MaxConcurrentDispatches: 3,
			}
			queue.RetryConfig = &pb.RetryConfig{
				MaxAttempts:      4,
				MinBackoff:       durationpb.New(time.Second),
				MaxBackoff:       durationpb.New(2 * time.Second),
				MaxRetryDuration: durationpb.New(time.Minute),
				MaxDoublings:     2,
			}
		}
		got, err := create(parent, queue)
		label := "create_" + id
		if a.code(label, codes.OK, err) {
			a.expect(label+"_name", got.GetName() == queue.GetName(), queue.GetName(), got.GetName())
			a.expect(label+"_state", got.GetState() == pb.Queue_RUNNING, pb.Queue_RUNNING, got.GetState())
			a.expect(label+"_rate_limits", proto.Equal(got.GetRateLimits(), queue.GetRateLimits()), queue.GetRateLimits(), got.GetRateLimits())
			a.expect(label+"_retry_config", proto.Equal(got.GetRetryConfig(), queue.GetRetryConfig()), queue.GetRetryConfig(), got.GetRetryConfig())
		}
		if id == "Z" {
			first = got
		}
		read, err := get(queue.GetName())
		if a.code("get_"+id, codes.OK, err) && got != nil {
			a.expect("get_"+id+"_matches_create", proto.Equal(read, got), got, read)
		}
	}
	slices.Sort(names)
	original := parent + collection + "Z"
	_, err := create(parent, &pb.Queue{Name: original})
	a.code("create_duplicate", codes.AlreadyExists, err)

	for _, tc := range []struct {
		label, parent string
		queue         *pb.Queue
	}{
		{"create_parent_empty", "", &pb.Queue{Name: original}},
		{"create_parent_empty_project", "projects//locations/us-east1", &pb.Queue{Name: original}},
		{"create_parent_empty_location", project + "/locations/", &pb.Queue{Name: original}},
		{"create_parent_wrong_collection", project + "/location/us-east1", &pb.Queue{Name: original}},
		{"create_parent_extra_segment", parent + "/extra", &pb.Queue{Name: original}},
		{"create_queue_missing", parent, nil},
		{"create_queue_and_parent_invalid", project, nil},
		{"create_name_not_under_parent", otherLocation, &pb.Queue{Name: original}},
		{"create_name_wrong_collection", parent, &pb.Queue{Name: parent + "/queue/Z"}},
		{"create_id_empty", parent, &pb.Queue{Name: parent + collection}},
		{"create_id_slash", parent, &pb.Queue{Name: parent + collection + "a/b"}},
		{"create_id_too_long", parent, &pb.Queue{Name: parent + collection + strings.Repeat("a", 101)}},
		{"create_id_disallowed_character", parent, &pb.Queue{Name: parent + collection + "a_b"}},
	} {
		_, err := create(tc.parent, tc.queue)
		a.code(tc.label, codes.InvalidArgument, err)
	}
	longParent := randomProject() + "/locations/us-east1"
	longName := longParent + collection + strings.Repeat("a", 100)
	long, err := create(longParent, &pb.Queue{Name: longName})
	if a.code("create_id_max_length", codes.OK, err) {
		a.expect("create_max_length_name", long.GetName() == longName, longName, long.GetName())
	}
	for _, tc := range []struct{ label, parent string }{
		{"other_location", otherLocation},
		{"other_project", otherProject},
	} {
		name := tc.parent + collection + "Z"
		got, err := create(tc.parent, &pb.Queue{Name: name})
		if a.code("create_"+tc.label, codes.OK, err) {
			a.expect("create_"+tc.label+"_name", got.GetName() == name, name, got.GetName())
		}
		read, err := get(name)
		if a.code("get_"+tc.label, codes.OK, err) && got != nil {
			a.expect("get_"+tc.label+"_matches_create", proto.Equal(read, got), got, read)
		}
	}
	read, err := get(original)
	if a.code("get_original_after_other_creates", codes.OK, err) && first != nil {
		a.expect("get_original_after_other_creates_matches_create", proto.Equal(read, first), first, read)
	}

	list := func(parent string, size int32, token string) (listPage, error) {
		resp, err := client.ListQueues(ctx, &pb.ListQueuesRequest{Parent: parent, PageSize: size, PageToken: token})
		return listPage{names: resourceNames(resp.GetQueues()), next: resp.GetNextPageToken()}, err
	}
	checkPagination(&a, list, parent, project, names)
	_, err = client.ListQueues(ctx, &pb.ListQueuesRequest{Parent: parent, Filter: "state=RUNNING"})
	a.code("list_filter", codes.Unimplemented, err)

	for _, tc := range []struct {
		label, name string
		code        codes.Code
	}{
		{"name_empty", "", codes.InvalidArgument},
		{"name_empty_project", "projects//locations/us-east1/queues/Z", codes.InvalidArgument},
		{"name_empty_location", project + "/locations//queues/Z", codes.InvalidArgument},
		{"name_empty_queue", parent + collection, codes.InvalidArgument},
		{"name_wrong_collection", parent + "/queue/Z", codes.InvalidArgument},
		{"name_extra_segment", original + "/tasks/a", codes.InvalidArgument},
		{"missing", parent + collection + "missing_", codes.NotFound},
	} {
		_, err := get(tc.name)
		a.code("get_"+tc.label, tc.code, err)
		_, err = remove(tc.name)
		a.code("delete_"+tc.label, tc.code, err)
	}
	deleted, err := remove(original)
	if a.code("delete", codes.OK, err) {
		a.expect("delete_empty_response", proto.Equal(deleted, &emptypb.Empty{}), &emptypb.Empty{}, deleted)
	}
	_, err = get(original)
	a.code("get_after_delete", codes.NotFound, err)
	remaining := slices.DeleteFunc(slices.Clone(names), func(name string) bool { return name == original })
	page, err := list(parent, 0, "")
	if a.code("list_after_delete", codes.OK, err) {
		a.page("list_after_delete", page, remaining, false, len(remaining))
	}
	for _, tc := range []struct{ label, parent string }{
		{"other_location", otherLocation},
		{"other_project", otherProject},
	} {
		page, err := list(tc.parent, 0, "")
		if a.code("list_"+tc.label+"_after_delete", codes.OK, err) {
			a.page("list_"+tc.label+"_after_delete", page, []string{tc.parent + collection + "Z"}, false, 1)
		}
	}
	recreated, err := create(parent, &pb.Queue{Name: original})
	if a.code("create_after_delete", codes.OK, err) {
		a.expect("create_after_delete_name", recreated.GetName() == original, original, recreated.GetName())
	}

	concurrentParent := randomProject() + "/locations/us-east1"
	checkConcurrentCreate(&a, func() error {
		_, err := create(concurrentParent, &pb.Queue{Name: concurrentParent + collection + "concurrent"})
		return err
	})

	limitParent := randomProject() + "/locations/us-east1"
	checkPageLimits(ctx, &a, list, limitParent, func(id string) (string, error) {
		name := limitParent + collection + id
		_, err := create(limitParent, &pb.Queue{Name: name})
		return name, err
	})
	return a.failures
}
