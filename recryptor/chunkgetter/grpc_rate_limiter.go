package chunkgetter

import (
	"context"

	"google.golang.org/grpc"

	codegen "github.com/elfinguard/elfinguard/recryptor/grpc"
	"github.com/elfinguard/elfinguard/types"
)

var _ types.RateLimiter = GrpcRateLimiter{}

type GrpcRateLimiter struct {
	client codegen.RateLimiterClient
}

func newGrpcRateLimiter(rpcAddr string) GrpcRateLimiter {
	conn, err := grpc.Dial(rpcAddr)
	if err != nil {
		panic(err) // TODO
	}

	client := codegen.NewRateLimiterClient(conn)
	return GrpcRateLimiter{client}
}

func (g GrpcRateLimiter) CanServe(removeAddr, path, query string, token, guide []byte) bool {
	req := codegen.RateLimitRequest{
		RemoteAddr: removeAddr,
		Path:       path,
		Query:      query,
		Token:      token,
		Guide:      guide,
	}
	reply, err := g.client.CanServe(context.Background(), &req)
	if err != nil {
		return false
	}
	return reply.Ok
}
