package chunkgetter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/elfinguard/elfinguard/recryptor/constants"
	"github.com/elfinguard/elfinguard/types"
)

func simpleHttpPost(client *http.Client, url string) ([]byte, error) {
	req, _ := http.NewRequest("POST", url, strings.NewReader(""))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected Status of Kubo Server: %v", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

type KuboChunkGetter struct {
	client *http.Client
	server string
}

func NewKuboChunkGetter(server string) *KuboChunkGetter {
	return &KuboChunkGetter{
		client: &http.Client{Timeout: 3 * time.Second},
		server: server,
	}
}

// https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-cat
func (kcg *KuboChunkGetter) GetChunk(token types.DecryptTaskToken, path string, index int) (chunk []byte, errStr string) {
	offset := index * constants.ChunkSize
	url := fmt.Sprintf("%s/api/v0/cat?arg=%s&offset=%d&length=%d&progress=true", kcg.server, path, offset, constants.ChunkSize)
	body, err := simpleHttpPost(kcg.client, url)
	if err != nil {
		return nil, err.Error()
	}
	return body, ""
}

type IpfsStat struct {
	CumulativeSize uint64
	Size           uint64
	SizeLocal      uint64
}

// https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-files-stat
func (kcg *KuboChunkGetter) GetTotalBytes(path string) (totalBytes int, errStr string) {
	url := fmt.Sprintf("%v/api/v0/files/stat?arg=%v", kcg.server, path)
	body, err := simpleHttpPost(kcg.client, url)
	if err != nil {
		return 0, err.Error()
	}
	var stat IpfsStat
	err = json.Unmarshal(body, &stat)
	if err != nil {
		return 0, err.Error()
	}
	return int(stat.CumulativeSize), ""
}
