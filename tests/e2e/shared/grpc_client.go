// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"errors"
	"fmt"
	"io"

	searchv1 "github.com/agntcy/dir/api/search/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type GrpcClient struct {
	BaseURL     string
	BearerToken string
}

func (c *GrpcClient) SearchCIDs(ctx context.Context) ([]*searchv1.SearchCIDsResponse, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	if c.BearerToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearerTokenCredentials{token: c.BearerToken}))
	}

	conn, err := grpc.NewClient(c.BaseURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("gRPC dial %s: %w", c.BaseURL, err)
	}

	defer conn.Close()

	client := searchv1.NewSearchServiceClient(conn)

	stream, err := client.SearchCIDs(ctx, &searchv1.SearchCIDsRequest{
		Queries: []*searchv1.RecordQuery{{
			Type:  searchv1.RecordQueryType_RECORD_QUERY_TYPE_NAME,
			Value: "test",
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("SearchCIDs: %w", err)
	}

	var responses []*searchv1.SearchCIDsResponse

	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return responses, nil
			}

			return nil, fmt.Errorf("stream.Recv: %w", err)
		}

		responses = append(responses, resp)
	}
}

type bearerTokenCredentials struct {
	token string
}

func (c bearerTokenCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + c.token,
	}, nil
}

func (c bearerTokenCredentials) RequireTransportSecurity() bool {
	return false
}

func GRPCStatusCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}

	st, ok := status.FromError(err)
	if !ok {
		return codes.Unknown
	}

	return st.Code()
}
