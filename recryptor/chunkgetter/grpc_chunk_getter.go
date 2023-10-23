package chunkgetter

import (
	"context"

	codegen "github.com/elfinguard/elfinguard/recryptor/grpc"
	"github.com/elfinguard/elfinguard/types"
	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc"
)

var _ types.ChunkGetter = GrpcChunkGetter{}

type GrpcChunkGetter struct {
	client codegen.ChunkGetterClient
}

func newGrpcChunkGetter(rpcAddr string) GrpcChunkGetter {
	conn, err := grpc.Dial(rpcAddr)
	if err != nil {
		panic(err) // TODO
	}

	client := codegen.NewChunkGetterClient(conn)
	return GrpcChunkGetter{client}
}

func (g GrpcChunkGetter) GetChunk(token types.DecryptTaskToken, path string, index int) (chunk []byte, errStr string) {
	contractAddr := common.HexToAddress(token.Contract)
	req := codegen.GetChunkRequest{
		Token: &codegen.DecryptTaskToken{
			ExpireTime:    token.ExpireTime,
			FileId:        token.FileId[:],
			RecryptorSalt: token.RecryptorSalt[:],
			Secret:        token.Secret[:],
			RemoteAddr:    token.RemoteAddr,
			ViewerAccount: token.ViewerAccount[:],
			Contract:      contractAddr[:],
		},
		Path:  path,
		Index: int64(index),
	}
	reply, err := g.client.GetChunk(context.Background(), &req)
	if err != nil {
		errStr = err.Error()
		return
	}
	return reply.Chunk, reply.ErrStr
}

func (g GrpcChunkGetter) GetTotalBytes(path string) (totalBytes int, errStr string) {
	req := codegen.GetChunkRequest{
		Path:  path,
		Index: -1,
	}
	reply, err := g.client.GetChunk(context.Background(), &req)
	if err != nil {
		errStr = err.Error()
		return
	}
	return int(reply.TotalBytes), reply.ErrStr
}
