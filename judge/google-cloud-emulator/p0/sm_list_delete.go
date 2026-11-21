package p0

import (
	"context"
	"maps"
	"slices"
	"strings"

	pb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func secretInput() *pb.Secret {
	return &pb.Secret{
		Name: "ignored",
		Replication: &pb.Replication{
			Replication: &pb.Replication_Automatic_{Automatic: &pb.Replication_Automatic{}},
		},
		Labels:      map[string]string{"team": "factory"},
		Annotations: map[string]string{"note": "p0"},
	}
}

func checkSecretCreate(ctx context.Context, a *assertions, client pb.SecretManagerServiceClient, parent string) *pb.Secret {
	const id = "A"
	input := secretInput()
	request := &pb.CreateSecretRequest{Parent: parent, SecretId: id, Secret: input}
	created, err := client.CreateSecret(ctx, request)
	if a.code("create_id_min_length", codes.OK, err) {
		name := parent + "/secrets/" + id
		a.expect("create_name", created.GetName() == name, name, created.GetName())
		a.expect("create_replication", proto.Equal(created.GetReplication(), input.GetReplication()), input.GetReplication(), created.GetReplication())
		a.expect("create_labels", maps.Equal(created.GetLabels(), input.GetLabels()), input.GetLabels(), created.GetLabels())
		a.expect("create_annotations", maps.Equal(created.GetAnnotations(), input.GetAnnotations()), input.GetAnnotations(), created.GetAnnotations())
		a.expect("create_time", validCreateTime(created.GetCreateTime()), "a valid non-zero timestamp", created.GetCreateTime())
	}
	_, err = client.CreateSecret(ctx, request)
	a.code("create_duplicate", codes.AlreadyExists, err)

	for _, tc := range []struct {
		label string
		req   *pb.CreateSecretRequest
	}{
		{"create_parent_empty", &pb.CreateSecretRequest{SecretId: id, Secret: input}},
		{"create_parent_empty_project", &pb.CreateSecretRequest{Parent: "projects/", SecretId: id, Secret: input}},
		{"create_parent_extra_segment", &pb.CreateSecretRequest{Parent: parent + "/locations/global", SecretId: id, Secret: input}},
		{"create_parent_wrong_collection", &pb.CreateSecretRequest{Parent: "project/example", SecretId: id, Secret: input}},
		{"create_id_empty", &pb.CreateSecretRequest{Parent: parent, Secret: input}},
		{"create_id_slash", &pb.CreateSecretRequest{Parent: parent, SecretId: "a/b", Secret: input}},
		{"create_id_too_long", &pb.CreateSecretRequest{Parent: parent, SecretId: strings.Repeat("a", 256), Secret: input}},
		{"create_id_disallowed_character", &pb.CreateSecretRequest{Parent: parent, SecretId: "a.b", Secret: input}},
		{"create_secret_missing", &pb.CreateSecretRequest{Parent: parent, SecretId: "missing"}},
		{"create_replication_missing", &pb.CreateSecretRequest{Parent: parent, SecretId: "missing", Secret: &pb.Secret{}}},
		{"create_invalid_parent_and_missing_secret", &pb.CreateSecretRequest{Parent: "projects/", SecretId: id}},
		{"create_validation_precedes_duplicate", &pb.CreateSecretRequest{Parent: parent, SecretId: id, Secret: &pb.Secret{}}},
	} {
		_, err := client.CreateSecret(ctx, tc.req)
		a.code(tc.label, codes.InvalidArgument, err)
	}

	longParent := randomProject()
	longID := strings.Repeat("a", 253) + "_-"
	long, err := client.CreateSecret(ctx, &pb.CreateSecretRequest{Parent: longParent, SecretId: longID, Secret: input})
	if a.code("create_id_max_length", codes.OK, err) {
		want := longParent + "/secrets/" + longID
		a.expect("create_max_length_name", long.GetName() == want, want, long.GetName())
	}

	concurrent := &pb.CreateSecretRequest{Parent: randomProject(), SecretId: "concurrent", Secret: input}
	checkConcurrentCreate(a, func() error {
		_, err := client.CreateSecret(ctx, concurrent)
		return err
	})
	return created
}

func checkSMListDelete(ctx context.Context, conn grpc.ClientConnInterface) []Failure {
	client := pb.NewSecretManagerServiceClient(conn)
	var a assertions
	parent, otherParent := randomProject(), randomProject()
	first := checkSecretCreate(ctx, &a, client, parent)
	names := []string{parent + "/secrets/A"}
	created := map[string]*pb.Secret{names[0]: first}
	input := secretInput()
	create := func(parent, id string) (*pb.Secret, error) {
		return client.CreateSecret(ctx, &pb.CreateSecretRequest{Parent: parent, SecretId: id, Secret: input})
	}
	for _, id := range []string{"z", "a", "X", "9"} {
		name := parent + "/secrets/" + id
		names = append(names, name)
		secret, err := create(parent, id)
		if a.code("seed_list_"+id, codes.OK, err) {
			created[name] = secret
		}
	}
	slices.Sort(names)
	other, err := create(otherParent, "A")
	if a.code("create_other_project", codes.OK, err) {
		want := otherParent + "/secrets/A"
		a.expect("create_other_project_name", other.GetName() == want, want, other.GetName())
	}

	list := func(parent string, size int32, token string) (listPage, error) {
		resp, err := client.ListSecrets(ctx, &pb.ListSecretsRequest{Parent: parent, PageSize: size, PageToken: token})
		return listPage{resourceNames(resp.GetSecrets()), resp.GetNextPageToken(), new(resp.GetTotalSize())}, err
	}
	checkPagination(&a, list, parent, parent+"/secrets", names)

	response, err := client.ListSecrets(ctx, &pb.ListSecretsRequest{Parent: parent})
	if a.code("list_contents", codes.OK, err) {
		for _, secret := range response.GetSecrets() {
			if want := created[secret.GetName()]; want != nil {
				a.expect("list_matches_create_"+strings.TrimPrefix(secret.GetName(), parent+"/secrets/"), proto.Equal(secret, want), want, secret)
			}
		}
	}
	_, err = client.ListSecrets(ctx, &pb.ListSecretsRequest{Parent: parent, Filter: "name:example"})
	a.code("list_filter", codes.Unimplemented, err)

	for _, tc := range []struct{ label, name string }{
		{"delete_name_empty", ""},
		{"delete_name_empty_project", "projects//secrets/A"},
		{"delete_name_empty_secret", parent + "/secrets/"},
		{"delete_name_wrong_collection", parent + "/secret/A"},
		{"delete_name_extra_segment", parent + "/secrets/A/versions/1"},
	} {
		_, err := client.DeleteSecret(ctx, &pb.DeleteSecretRequest{Name: tc.name})
		a.code(tc.label, codes.InvalidArgument, err)
	}
	_, err = client.DeleteSecret(ctx, &pb.DeleteSecretRequest{Name: parent + "/secrets/missing.secret"})
	a.code("delete_missing", codes.NotFound, err)

	toDelete := parent + "/secrets/A"
	deleted, err := client.DeleteSecret(ctx, &pb.DeleteSecretRequest{Name: toDelete, Etag: "ignored"})
	if a.code("delete_ignores_etag", codes.OK, err) {
		a.expect("delete_empty_response", proto.Equal(deleted, &emptypb.Empty{}), &emptypb.Empty{}, deleted)
	}
	remaining := slices.DeleteFunc(slices.Clone(names), func(name string) bool { return name == toDelete })
	page, err := list(parent, 0, "")
	if a.code("list_after_delete", codes.OK, err) {
		a.page("list_after_delete", page, remaining, false, len(remaining))
	}
	page, err = list(otherParent, 0, "")
	if a.code("list_other_project_after_delete", codes.OK, err) {
		a.page("list_other_project_after_delete", page, []string{otherParent + "/secrets/A"}, false, 1)
	}
	recreated, err := create(parent, "A")
	if a.code("create_after_delete", codes.OK, err) {
		a.expect("create_after_delete_name", recreated.GetName() == toDelete, toDelete, recreated.GetName())
	}

	limitParent := randomProject()
	checkPageLimits(ctx, &a, list, limitParent, func(id string) (string, error) {
		_, err := create(limitParent, id)
		return limitParent + "/secrets/" + id, err
	})
	return a.failures
}
