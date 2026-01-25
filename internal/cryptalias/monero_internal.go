package cryptalias

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	cryptaliasv1 "github.com/kaigoh/cryptalias/proto/cryptalias/v1"
	"github.com/kaigoh/cryptalias/wallet_interfaces/xmr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const internalBufSize = 1024 * 1024

type internalMoneroGRPC struct {
	client cryptaliasv1.WalletServiceClient
	svc    *moneroWalletService
}

func newInternalMoneroGRPC(endpoint TokenEndpointConfig) (*internalMoneroGRPC, error) {
	lis := bufconn.Listen(internalBufSize)
	svc := newMoneroWalletService(endpoint)

	s := grpc.NewServer()
	cryptaliasv1.RegisterWalletServiceServer(s, svc)
	go func() {
		_ = s.Serve(lis)
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.DialContext(context.Background(), "bufnet-monero",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	client := cryptaliasv1.NewWalletServiceClient(conn)
	return &internalMoneroGRPC{client: client, svc: svc}, nil
}

func (i *internalMoneroGRPC) Client(endpoint TokenEndpointConfig) cryptaliasv1.WalletServiceClient {
	i.svc.SetEndpoint(endpoint)
	return i.client
}

type moneroWalletService struct {
	cryptaliasv1.UnimplementedWalletServiceServer
	endpoint atomic.Value // TokenEndpointConfig
}

func newMoneroWalletService(endpoint TokenEndpointConfig) *moneroWalletService {
	s := &moneroWalletService{}
	s.SetEndpoint(endpoint)
	return s
}

func (s *moneroWalletService) SetEndpoint(endpoint TokenEndpointConfig) {
	s.endpoint.Store(endpoint)
}

func (s *moneroWalletService) GetAddress(ctx context.Context, req *cryptaliasv1.WalletAddressRequest) (*cryptaliasv1.WalletAddressResponse, error) {
	ep, _ := s.endpoint.Load().(TokenEndpointConfig)
	client := xmr.NewWalletRPC(ep.EndpointAddress, ep.Username, ep.Password)
	if !client.Enabled() {
		return nil, fmt.Errorf("monero wallet rpc not configured")
	}

	label := req.GetDomain() + ":" + req.GetAlias()
	if tag := req.GetTag(); tag != "" {
		label += "+" + tag
	}

	addrBytes, _, err := client.CreateAddress(ctx, 0, []byte(label))
	if err != nil {
		return nil, err
	}
	addr := string(addrBytes)
	if addr == "" {
		return nil, fmt.Errorf("monero wallet rpc returned empty address")
	}
	return &cryptaliasv1.WalletAddressResponse{Address: addr}, nil
}

func (s *moneroWalletService) Health(context.Context, *cryptaliasv1.HealthRequest) (*cryptaliasv1.HealthResponse, error) {
	return &cryptaliasv1.HealthResponse{Ok: true, Message: "ok"}, nil
}
