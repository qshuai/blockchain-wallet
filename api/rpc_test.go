package api

import (
	"context"
	"testing"

	"github.com/qshuai/blockchain-wallet/api/pb"
	"google.golang.org/grpc"
)

func TestServeAPI(t *testing.T) {
	conn, err := grpc.Dial("127.0.0.1:8234", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		t.Errorf("connect to grpc serve failed: %s", err)
	}

	client := pb.NewAPIClient(conn)

	// create a new address
	address, err := client.NewAddress(context.Background(), &pb.KeySelection{Purpose: pb.KeyPurpose_INTERNAL})
	if err != nil {
		t.Errorf("create a new address failed: %s", err)
	}
	t.Logf("The new address: %s", address.String())

	// get balance for the new address
	balance, err := client.Balance(context.Background(), &pb.Empty{})
	if err != nil {
		t.Errorf("fetch balance for the new address failed: %s", err)
	}
	t.Logf("The balance of %s is %s", address.String(), balance.String())
}
