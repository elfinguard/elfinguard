package chunkgetter

import (
	"context"

	"github.com/elfinguard/elfinguard/types"
	"github.com/smallnest/rpcx/client"
)

var _ types.ChunkGetter = RpcxChunkGetter{}

type RpcxChunkGetter struct {
	xclient client.XClient
}

func newRpcxChunkGetter(rpcAddr string) RpcxChunkGetter {
	d, _ := client.NewPeer2PeerDiscovery("tcp@"+rpcAddr, "")
	xclient := client.NewXClient("ChunkGetter", client.Failtry, client.RandomSelect, d, client.DefaultOption)
	return RpcxChunkGetter{xclient: xclient}
}

func (g RpcxChunkGetter) GetChunk(token types.DecryptTaskToken, path string, index int) (chunk []byte, errStr string) {
	req := types.RpcxReq{Path: path, Index: index, DecryptTaskToken: token}

	var resp types.RpcxResp
	err := g.xclient.Call(context.Background(), "GetChunk", req, &resp)
	if err != nil {
		errStr = err.Error()
		return
	}
	return resp.Chunk, resp.ErrStr
}

func (g RpcxChunkGetter) GetTotalBytes(path string) (totalBytes int, errStr string) {
	req := types.RpcxReq{Path: path, Index: -1}
	var resp types.RpcxResp
	err := g.xclient.Call(context.Background(), "GetChunk", req, &resp)
	if err != nil {
		errStr = err.Error()
		return
	}
	return resp.TotalBytes, resp.ErrStr
}
