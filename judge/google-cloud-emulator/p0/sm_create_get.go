package p0

import (
	"context"
	"maps"
	"strings"
	"sync"

	pb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func checkSMCreateGet(ctx context.Context, conn grpc.ClientConnInterface) []Failure {
	client := pb.NewSecretManagerServiceClient(conn)
	var checks assertions
	expect, expectCode := checks.expect, checks.code

	parent, otherParent := randomProject(), randomProject()
	const id = "Example_1-secret"
	name := parent + "/secrets/" + id
	input := &pb.Secret{
		Name: parent + "/secrets/ignored",
		Replication: &pb.Replication{
			Replication: &pb.Replication_Automatic_{Automatic: &pb.Replication_Automatic{}},
		},
		Labels:      map[string]string{"team": "factory"},
		Annotations: map[string]string{"note": "create-get"},
	}
	request := &pb.CreateSecretRequest{Parent: parent, SecretId: id, Secret: input}
	created, err := client.CreateSecret(ctx, request)
	createdOK := expectCode("create", codes.OK, err)
	if createdOK {
		expect("create_name", created.GetName() == name, name, created.GetName())
		expect("create_replication", proto.Equal(created.GetReplication(), input.GetReplication()), input.GetReplication(), created.GetReplication())
		expect("create_labels", maps.Equal(created.GetLabels(), input.GetLabels()), input.GetLabels(), created.GetLabels())
		expect("create_annotations", maps.Equal(created.GetAnnotations(), input.GetAnnotations()), input.GetAnnotations(), created.GetAnnotations())
		ts := created.GetCreateTime()
		expect("create_time", ts != nil && ts.IsValid() && (ts.GetSeconds() != 0 || ts.GetNanos() != 0) && !ts.AsTime().IsZero(), "a valid non-zero timestamp", ts)
	}
	got, err := client.GetSecret(ctx, &pb.GetSecretRequest{Name: name})
	if expectCode("get", codes.OK, err) && createdOK {
		expect("get_matches_create", proto.Equal(got, created), created, got)
	}
	_, err = client.CreateSecret(ctx, request)
	expectCode("create_duplicate", codes.AlreadyExists, err)
	_, err = client.GetSecret(ctx, &pb.GetSecretRequest{Name: input.GetName()})
	expectCode("get_ignored_request_name", codes.NotFound, err)
	_, err = client.GetSecret(ctx, &pb.GetSecretRequest{Name: parent + "/secrets/missing.secret"})
	expectCode("get_missing", codes.NotFound, err)

	for _, tt := range []struct {
		name string
		req  *pb.CreateSecretRequest
	}{
		{"create_parent_empty", &pb.CreateSecretRequest{SecretId: id, Secret: input}},
		{"create_parent_wrong_collection", &pb.CreateSecretRequest{Parent: "project/example", SecretId: id, Secret: input}},
		{"create_parent_empty_project", &pb.CreateSecretRequest{Parent: "projects/", SecretId: id, Secret: input}},
		{"create_parent_extra_segment", &pb.CreateSecretRequest{Parent: parent + "/locations/global", SecretId: id, Secret: input}},
		{"create_id_empty", &pb.CreateSecretRequest{Parent: parent, Secret: input}},
		{"create_id_slash", &pb.CreateSecretRequest{Parent: parent, SecretId: "a/b", Secret: input}},
		{"create_id_too_long", &pb.CreateSecretRequest{Parent: parent, SecretId: strings.Repeat("a", 256), Secret: input}},
		{"create_id_disallowed_character", &pb.CreateSecretRequest{Parent: parent, SecretId: "a.b", Secret: input}},
		{"create_secret_missing", &pb.CreateSecretRequest{Parent: parent, SecretId: "missing"}},
		{"create_replication_missing", &pb.CreateSecretRequest{Parent: parent, SecretId: "missing", Secret: &pb.Secret{}}},
		{"create_invalid_parent_and_missing_secret", &pb.CreateSecretRequest{Parent: "projects/", SecretId: id}},
		{"create_validation_precedes_duplicate", &pb.CreateSecretRequest{Parent: parent, SecretId: id, Secret: &pb.Secret{}}},
	} {
		_, err := client.CreateSecret(ctx, tt.req)
		expectCode(tt.name, codes.InvalidArgument, err)
	}

	longID := strings.Repeat("a", 255)
	long, err := client.CreateSecret(ctx, &pb.CreateSecretRequest{Parent: parent, SecretId: longID, Secret: input})
	if expectCode("create_id_max_length", codes.OK, err) {
		want := parent + "/secrets/" + longID
		expect("create_max_length_name", long.GetName() == want, want, long.GetName())
	}

	for _, tt := range []struct{ name, resource string }{
		{"get_name_empty", ""},
		{"get_name_empty_project", "projects//secrets/example"},
		{"get_name_empty_secret", parent + "/secrets/"},
		{"get_name_wrong_collection", parent + "/secret/example"},
		{"get_name_extra_segment", name + "/versions/1"},
	} {
		_, err := client.GetSecret(ctx, &pb.GetSecretRequest{Name: tt.resource})
		expectCode(tt.name, codes.InvalidArgument, err)
	}

	otherName := otherParent + "/secrets/" + id
	otherInput := proto.CloneOf(input)
	otherInput.Labels["team"] = "other"
	other, err := client.CreateSecret(ctx, &pb.CreateSecretRequest{Parent: otherParent, SecretId: id, Secret: otherInput})
	otherOK := expectCode("create_other_project", codes.OK, err)
	if otherOK {
		expect("create_other_project_name", other.GetName() == otherName, otherName, other.GetName())
		expect("create_other_project_labels", maps.Equal(other.GetLabels(), otherInput.GetLabels()), otherInput.GetLabels(), other.GetLabels())
	}
	for _, tt := range []struct {
		name, resource string
		createdOK      bool
		created        *pb.Secret
	}{
		{"get_original_project", name, createdOK, created},
		{"get_other_project", otherName, otherOK, other},
	} {
		got, err := client.GetSecret(ctx, &pb.GetSecretRequest{Name: tt.resource})
		if expectCode(tt.name, codes.OK, err) && tt.createdOK {
			expect(tt.name+"_matches_create", proto.Equal(got, tt.created), tt.created, got)
		}
	}

	const concurrentCreates = 8
	var wg sync.WaitGroup
	var results [concurrentCreates]codes.Code
	concurrent := &pb.CreateSecretRequest{Parent: parent, SecretId: "concurrent", Secret: input}
	for i := range results {
		wg.Go(func() {
			_, err := client.CreateSecret(ctx, concurrent)
			results[i] = status.Code(err)
		})
	}
	wg.Wait()
	var successes, duplicates int
	for _, code := range results {
		switch code {
		case codes.OK:
			successes++
		case codes.AlreadyExists:
			duplicates++
		}
	}
	expect("create_concurrent_duplicate", successes == 1 && duplicates == concurrentCreates-1,
		"one OK and seven AlreadyExists", results)
	return checks.failures
}
