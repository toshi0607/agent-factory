package p0

import (
	"bytes"
	"context"
	"hash/crc32"
	"strconv"
	"sync"

	pb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

func checkSMVersions(ctx context.Context, conn grpc.ClientConnInterface) []Failure {
	client := pb.NewSecretManagerServiceClient(conn)
	var a assertions
	project := randomProject()
	checkSecretCreate(ctx, &a, client, project)
	parent := project + "/secrets/A"
	independent := project + "/secrets/independent"
	empty := project + "/secrets/empty"
	missing := project + "/secrets/missing"

	for _, id := range []string{"independent", "empty"} {
		_, err := client.CreateSecret(ctx, &pb.CreateSecretRequest{Parent: project, SecretId: id, Secret: secretInput()})
		a.code("create_"+id+"_secret", codes.OK, err)
	}
	add := func(parent string, payload *pb.SecretPayload) (*pb.SecretVersion, error) {
		return client.AddSecretVersion(ctx, &pb.AddSecretVersionRequest{Parent: parent, Payload: payload})
	}
	get := func(name string) (*pb.SecretVersion, error) {
		return client.GetSecretVersion(ctx, &pb.GetSecretVersionRequest{Name: name})
	}
	access := func(name string) (*pb.AccessSecretVersionResponse, error) {
		return client.AccessSecretVersion(ctx, &pb.AccessSecretVersionRequest{Name: name})
	}
	table := crc32.MakeTable(crc32.Castagnoli)
	crc := func(data []byte) int64 { return int64(crc32.Checksum(data, table)) }
	data := []byte{0, 0x80, 0xff, 'A'}
	badCRC := &pb.SecretPayload{Data: data, DataCrc32C: new(crc(data) + 1)}
	for _, tc := range []struct {
		label, parent string
		payload       *pb.SecretPayload
		code          codes.Code
	}{
		{"add_parent_empty", "", &pb.SecretPayload{}, codes.InvalidArgument},
		{"add_parent_empty_project", "projects//secrets/A", &pb.SecretPayload{}, codes.InvalidArgument},
		{"add_parent_empty_secret", project + "/secrets/", &pb.SecretPayload{}, codes.InvalidArgument},
		{"add_parent_wrong_collection", project + "/secret/A", &pb.SecretPayload{}, codes.InvalidArgument},
		{"add_parent_extra_segment", parent + "/versions/1", &pb.SecretPayload{}, codes.InvalidArgument},
		{"add_invalid_parent_and_missing_payload", project, nil, codes.InvalidArgument},
		{"add_missing_payload", parent, nil, codes.InvalidArgument},
		{"add_wrong_checksum", parent, badCRC, codes.InvalidArgument},
		{"add_missing_secret", missing, &pb.SecretPayload{}, codes.NotFound},
		{"add_payload_validation_precedes_lookup", missing, nil, codes.InvalidArgument},
		{"add_checksum_validation_precedes_lookup", missing, badCRC, codes.InvalidArgument},
	} {
		_, err := add(tc.parent, tc.payload)
		a.code(tc.label, tc.code, err)
	}

	checkRead := func(label, requestName, wantName string, data []byte, added *pb.SecretVersion) {
		got, err := access(requestName)
		if a.code("access_"+label, codes.OK, err) {
			a.expect("access_"+label+"_name", got.GetName() == wantName, wantName, got.GetName())
			payload := got.GetPayload()
			a.expect("access_"+label+"_data", payload != nil && bytes.Equal(payload.GetData(), data), data, payload.GetData())
			wantCRC := crc(data)
			a.expect("access_"+label+"_checksum", payload != nil && payload.DataCrc32C != nil && payload.GetDataCrc32C() == wantCRC, wantCRC, payload)
		}
		version, err := get(requestName)
		if a.code("get_"+label, codes.OK, err) && added != nil {
			a.expect("get_"+label+"_matches_add", proto.Equal(version, added), added, version)
		}
	}

	type versionRead struct {
		label, name string
		data        []byte
		added       *pb.SecretVersion
	}
	var reads []versionRead
	// Interleave writes to prove version numbers are allocated per secret.
	for _, tc := range []struct {
		label, parent, number string
		payload               *pb.SecretPayload
	}{
		{"first", parent, "1", &pb.SecretPayload{Data: data}},
		{"independent", independent, "1", &pb.SecretPayload{DataCrc32C: new(int64(0))}},
		{"empty_data", parent, "2", &pb.SecretPayload{}},
		{"correct_checksum", parent, "3", &pb.SecretPayload{Data: []byte("latest"), DataCrc32C: new(crc([]byte("latest")))}},
	} {
		name := tc.parent + "/versions/" + tc.number
		added, err := add(tc.parent, tc.payload)
		if a.code("add_"+tc.label, codes.OK, err) {
			a.expect("add_"+tc.label+"_name", added.GetName() == name, name, added.GetName())
			a.expect("add_"+tc.label+"_state", added.GetState() == pb.SecretVersion_ENABLED, pb.SecretVersion_ENABLED, added.GetState())
			a.expect("add_"+tc.label+"_create_time", validCreateTime(added.GetCreateTime()), "a valid non-zero timestamp", added.GetCreateTime())
			hasChecksum := tc.payload.DataCrc32C != nil
			a.expect("add_"+tc.label+"_client_checksum", added.GetClientSpecifiedPayloadChecksum() == hasChecksum, hasChecksum, added.GetClientSpecifiedPayloadChecksum())
		}
		reads = append(reads, versionRead{tc.label, name, tc.payload.GetData(), added})
	}

	for _, tc := range []struct {
		label, name string
		code        codes.Code
	}{
		{"name_empty", "", codes.InvalidArgument},
		{"name_empty_project", "projects//secrets/A/versions/1", codes.InvalidArgument},
		{"name_empty_secret", project + "/secrets//versions/1", codes.InvalidArgument},
		{"name_wrong_collection", parent + "/version/1", codes.InvalidArgument},
		{"name_extra_segment", parent + "/versions/1/extra", codes.InvalidArgument},
		{"version_zero", parent + "/versions/0", codes.InvalidArgument},
		{"version_leading_zero", parent + "/versions/01", codes.InvalidArgument},
		{"version_negative", parent + "/versions/-1", codes.InvalidArgument},
		{"version_letters", parent + "/versions/abc", codes.InvalidArgument},
		{"version_empty", parent + "/versions/", codes.InvalidArgument},
		{"missing_version", parent + "/versions/4", codes.NotFound},
		{"missing_secret", missing + "/versions/1", codes.NotFound},
		{"latest_without_versions", empty + "/versions/latest", codes.NotFound},
	} {
		_, err := access(tc.name)
		a.code("access_"+tc.label, tc.code, err)
		_, err = get(tc.name)
		a.code("get_"+tc.label, tc.code, err)
	}

	for _, read := range reads {
		checkRead(read.label, read.name, read.name, read.data, read.added)
	}
	latest := reads[len(reads)-1]
	checkRead("latest", parent+"/versions/latest", latest.name, latest.data, latest.added)

	// Exercise competing writers separately so the latest and missing-version
	// checks above still refer to a fixed set of three versions.
	var wg sync.WaitGroup
	var results [8]struct {
		name string
		err  error
	}
	for i := range results {
		wg.Go(func() {
			version, err := add(parent, &pb.SecretPayload{})
			results[i].name, results[i].err = version.GetName(), err
		})
	}
	wg.Wait()
	names := make(map[string]bool, len(results))
	for i, result := range results {
		a.code("add_concurrent_"+strconv.Itoa(i+1), codes.OK, result.err)
		names[result.name] = true
	}
	for i := range results {
		want := parent + "/versions/" + strconv.Itoa(i+4)
		a.expect("add_concurrent_version_"+strconv.Itoa(i+4), names[want], want, names)
	}
	return a.failures
}
