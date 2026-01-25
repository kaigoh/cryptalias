package cryptalias

import (
	"fmt"
	"sync"

	cryptaliasv1 "github.com/kaigoh/cryptalias/proto/cryptalias/v1"
)

type internalWallets struct {
	mu     sync.Mutex
	monero *internalMoneroGRPC
}

func newInternalWallets() *internalWallets {
	return &internalWallets{}
}

func (w *internalWallets) moneroClient(endpoint TokenEndpointConfig) (cryptaliasv1.WalletServiceClient, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.monero == nil {
		grpcSvc, err := newInternalMoneroGRPC(endpoint)
		if err != nil {
			return nil, err
		}
		w.monero = grpcSvc
	}
	if w.monero == nil {
		return nil, fmt.Errorf("internal monero service unavailable")
	}
	return w.monero.Client(endpoint), nil
}
