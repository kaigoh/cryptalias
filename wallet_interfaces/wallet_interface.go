package walletinterfaces

import "context"

type Wallet interface {
	Enabled() (bool, error)
	OpenWallet(ctx context.Context, name []byte, password []byte) error
	CloseWallet(ctx context.Context, name []byte) error
	CreateAddress(ctx context.Context, account uint64, label []byte) ([]byte, uint64, error)
	GetAddress(ctx context.Context, account uint64, index uint64) ([]byte, error)
}
