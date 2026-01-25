package cryptalias

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cryptaliasv1 "github.com/kaigoh/cryptalias/proto/cryptalias/v1"
	"gitlab.com/moneropay/go-monero/walletrpc"
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
	mu       sync.Mutex
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
	client := s.newWalletRPC(ep.EndpointAddress, ep.Username, ep.Password)

	// monero-wallet-rpc can only have one wallet open at a time; serialize access.
	s.mu.Lock()
	defer s.mu.Unlock()

	accountIndex := uint64(0)
	if req.AccountIndex != nil {
		accountIndex = req.GetAccountIndex()
	}

	if strings.TrimSpace(ep.WalletFile) != "" {
		if err := client.OpenWallet(ctx, &walletrpc.OpenWalletRequest{
			Filename: ep.WalletFile,
			Password: ep.WalletPassword,
		}); err != nil {
			return nil, err
		}
		defer func() { _ = client.CloseWallet(ctx) }()
	}

	label := req.GetDomain() + ":" + req.GetAlias()
	if tag := req.GetTag(); tag != "" {
		label += "+" + tag
	}

	resp, err := client.CreateAddress(ctx, &walletrpc.CreateAddressRequest{
		AccountIndex: accountIndex,
		Label:        label,
	})
	if err != nil {
		return nil, err
	}
	addr := resp.Address
	if addr == "" {
		return nil, fmt.Errorf("monero wallet rpc returned empty address")
	}
	return &cryptaliasv1.WalletAddressResponse{Address: addr}, nil
}

func (s *moneroWalletService) Health(context.Context, *cryptaliasv1.HealthRequest) (*cryptaliasv1.HealthResponse, error) {
	return &cryptaliasv1.HealthResponse{Ok: true, Message: "ok"}, nil
}

func (s *moneroWalletService) newWalletRPC(url, user, password string) *walletrpc.Client {
	headers := map[string]string{}
	if user != "" || password != "" {
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		headers["Authorization"] = "Basic " + token
	}

	client := walletrpc.New(walletrpc.Config{
		Address:       url,
		CustomHeaders: headers,
		Client:        &http.Client{Timeout: 10 * time.Second},
	})

	return client
}
