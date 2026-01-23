package xmr

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"gitlab.com/moneropay/go-monero/walletrpc"
)

type WalletRPC struct {
	client *walletrpc.Client
}

func NewWalletRPC(url, user, password string) *WalletRPC {
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

	return &WalletRPC{client: client}
}

func (w *WalletRPC) Enabled() bool {
	return w != nil && w.client != nil
}

func (w *WalletRPC) OpenWallet(ctx context.Context, name []byte, password []byte) error {
	if w.client == nil {
		return errors.New("wallet rpc not configured")
	}
	return w.client.OpenWallet(ctx, &walletrpc.OpenWalletRequest{Filename: string(name), Password: string(password)})
}

func (w *WalletRPC) CloseWallet(ctx context.Context, name []byte, password []byte) error {
	if w.client == nil {
		return errors.New("wallet rpc not configured")
	}
	return w.client.CloseWallet(ctx)
}

func (w *WalletRPC) CreateAddress(ctx context.Context, account uint64, label []byte) ([]byte, uint64, error) {
	if w.client == nil {
		return nil, 0, errors.New("wallet rpc not configured")
	}
	resp, err := w.client.CreateAddress(ctx, &walletrpc.CreateAddressRequest{
		AccountIndex: 0,
		Label:        string(label),
	})
	if err != nil {
		return nil, 0, err
	}
	return []byte(resp.Address), resp.AddressIndex, nil
}

func (w *WalletRPC) GetAddress(ctx context.Context, account uint64, index uint64) ([]byte, error) {
	if w.client == nil {
		return nil, errors.New("wallet rpc not configured")
	}
	resp, err := w.client.GetAddress(ctx, &walletrpc.GetAddressRequest{
		AccountIndex: account,
		AddressIndex: []uint64{index},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Addresses) == 0 {
		return nil, errors.New("address not found")
	}
	return []byte(resp.Addresses[0].Address), nil
}
