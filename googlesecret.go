package googlesecret

import (
	"context"
	"fmt"
	"hash/crc32"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type Secret struct {
	Version string
	Name    string
	Value   string
}

func New(ctx context.Context, projectID, secretName, version string) (*Secret, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	defer client.Close()

	resName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", projectID, secretName, version)

	v, err := getSecretValue(ctx, client, resName)
	if err != nil {
		return nil, err
	}

	return &Secret{
		Version: version,
		Name:    secretName,
		Value:   v,
	}, nil
}

func getSecretValue(ctx context.Context, client *secretmanager.Client, resourceName string) (string, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: resourceName,
	}
	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret version: %w", err)
	}

	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(result.Payload.Data, crc32c))
	if checksum != *result.Payload.DataCrc32C {
		return "", fmt.Errorf("data corruption detected")
	}
	return string(result.Payload.Data), nil
}
