package cryptalias

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	cryptaliasv1 "github.com/kaigoh/cryptalias/proto/cryptalias/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type grpcWalletClient struct {
	mu      sync.Mutex
	clients map[string]cryptaliasv1.WalletServiceClient
	conns   map[string]*grpc.ClientConn
}

func newGRPCWalletClient() *grpcWalletClient {
	return &grpcWalletClient{
		clients: map[string]cryptaliasv1.WalletServiceClient{},
		conns:   map[string]*grpc.ClientConn{},
	}
}

func (c *grpcWalletClient) GetAddress(ctx context.Context, endpoint TokenEndpointConfig, in dynamicAliasInput) (string, error) {
	client, err := c.clientFor(endpoint.EndpointAddress)
	if err != nil {
		return "", err
	}

	ctx = withEndpointAuth(ctx, endpoint)
	resp, err := client.GetAddress(ctx, &cryptaliasv1.WalletAddressRequest{
		Ticker: in.Ticker,
		Alias:  in.Alias,
		Tag:    in.Tag,
		Domain: in.Domain,
	})
	if err != nil {
		return "", err
	}
	if resp.GetAddress() == "" {
		return "", fmt.Errorf("wallet service returned empty address")
	}
	return resp.GetAddress(), nil
}

func (c *grpcWalletClient) clientFor(addr string) (cryptaliasv1.WalletServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if client, ok := c.clients[addr]; ok {
		return client, nil
	}

	conn, err := grpc.DialContext(context.Background(), addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	client := cryptaliasv1.NewWalletServiceClient(conn)
	c.clients[addr] = client
	c.conns[addr] = conn
	return client, nil
}

func withEndpointAuth(ctx context.Context, endpoint TokenEndpointConfig) context.Context {
	if endpoint.Token != "" {
		return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+endpoint.Token))
	}
	if endpoint.Username != "" || endpoint.Password != "" {
		token := base64.StdEncoding.EncodeToString([]byte(endpoint.Username + ":" + endpoint.Password))
		return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Basic "+token))
	}
	return ctx
}
