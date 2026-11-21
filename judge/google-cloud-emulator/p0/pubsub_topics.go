package p0

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	pb "cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func checkPubSubTopics(ctx context.Context, conn grpc.ClientConnInterface) []Failure {
	client := pb.NewPublisherClient(conn)
	var a assertions
	parent, otherParent := randomProject(), randomProject()
	const collection = "/topics/"
	create := func(topic *pb.Topic) (*pb.Topic, error) {
		return client.CreateTopic(ctx, topic)
	}
	get := func(name string) (*pb.Topic, error) {
		return client.GetTopic(ctx, &pb.GetTopicRequest{Topic: name})
	}
	remove := func(name string) (*emptypb.Empty, error) {
		return client.DeleteTopic(ctx, &pb.DeleteTopicRequest{Topic: name})
	}
	createAndCheck := func(label string, input *pb.Topic) *pb.Topic {
		got, err := create(input)
		if a.code(label, codes.OK, err) {
			a.expect(label+"_name", got.GetName() == input.GetName(), input.GetName(), got.GetName())
			a.expect(label+"_labels", maps.Equal(got.GetLabels(), input.GetLabels()), input.GetLabels(), got.GetLabels())
			a.expect(label+"_state", got.GetState() == pb.Topic_ACTIVE, pb.Topic_ACTIVE, got.GetState())
		}
		return got
	}
	var names []string
	var first *pb.Topic
	for _, tc := range []struct{ label, id string }{
		{"min_length", "Zoo"},
		{"max_length", strings.Repeat("a", 255)},
		{"mixed_case", "Apple"},
		{"lowercase", "apple"},
		{"with_digits", "z12"},
	} {
		input := &pb.Topic{
			Name:   parent + collection + tc.id,
			Labels: map[string]string{"team": "factory"},
			State:  pb.Topic_INGESTION_RESOURCE_ERROR,
		}
		names = append(names, input.GetName())
		got := createAndCheck("create_"+tc.label, input)
		if tc.label == "min_length" {
			first = got
		}
		read, err := get(input.GetName())
		if a.code("get_"+tc.label, codes.OK, err) && got != nil {
			a.expect("get_"+tc.label+"_matches_create", proto.Equal(read, got), got, read)
		}
	}
	slices.Sort(names)
	original := parent + collection + "Zoo"
	_, err := create(&pb.Topic{Name: original})
	a.code("create_duplicate", codes.AlreadyExists, err)

	for _, tc := range []struct{ label, name string }{
		{"name_empty", ""},
		{"name_empty_project", "projects//topics/Zoo"},
		{"name_empty_topic", parent + collection},
		{"name_wrong_collection", parent + "/topic/Zoo"},
		{"name_extra_segment", original + "/extra"},
		{"id_too_short", parent + collection + "ab"},
		{"id_too_long", parent + collection + strings.Repeat("a", 256)},
		{"id_must_start_with_letter", parent + collection + "1ab"},
		{"id_reserved_prefix", parent + collection + "googTest"},
		{"id_disallowed_character", parent + collection + "ab!"},
	} {
		_, err := create(&pb.Topic{Name: tc.name})
		a.code("create_"+tc.label, codes.InvalidArgument, err)
	}
	specialParent := randomProject()
	for _, ch := range "-_.~+%" {
		name := specialParent + collection + "Ab" + string(ch)
		createAndCheck(fmt.Sprintf("create_id_character_%02x", ch), &pb.Topic{Name: name})
	}

	otherName := otherParent + collection + "Zoo"
	other := createAndCheck("create_other_project", &pb.Topic{
		Name: otherName, Labels: map[string]string{"team": "other"},
	})
	read, err := get(otherName)
	if a.code("get_other_project", codes.OK, err) && other != nil {
		a.expect("get_other_project_matches_create", proto.Equal(read, other), other, read)
	}
	read, err = get(original)
	if a.code("get_original_after_other_create", codes.OK, err) && first != nil {
		a.expect("get_original_after_other_create_matches_create", proto.Equal(read, first), first, read)
	}

	list := func(parent string, size int32, token string) (listPage, error) {
		resp, err := client.ListTopics(ctx, &pb.ListTopicsRequest{Project: parent, PageSize: size, PageToken: token})
		return listPage{names: resourceNames(resp.GetTopics()), next: resp.GetNextPageToken()}, err
	}
	checkPagination(&a, list, parent, parent+"/topics", names)

	for _, tc := range []struct {
		label, name string
		code        codes.Code
	}{
		{"name_empty", "", codes.InvalidArgument},
		{"name_empty_project", "projects//topics/Zoo", codes.InvalidArgument},
		{"name_empty_topic", parent + collection, codes.InvalidArgument},
		{"name_wrong_collection", parent + "/topic/Zoo", codes.InvalidArgument},
		{"name_extra_segment", original + "/extra", codes.InvalidArgument},
		{"missing", parent + collection + "goog!", codes.NotFound},
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
	page, err = list(otherParent, 0, "")
	if a.code("list_other_project_after_delete", codes.OK, err) {
		a.page("list_other_project_after_delete", page, []string{otherName}, false, 1)
	}
	createAndCheck("create_after_delete", &pb.Topic{Name: original})

	concurrent := &pb.Topic{Name: randomProject() + collection + "concurrent"}
	checkConcurrentCreate(&a, func() error {
		_, err := create(concurrent)
		return err
	})
	limitParent := randomProject()
	checkPageLimits(ctx, &a, list, limitParent, func(id string) (string, error) {
		name := limitParent + collection + id
		_, err := create(&pb.Topic{Name: name})
		return name, err
	})
	return a.failures
}
