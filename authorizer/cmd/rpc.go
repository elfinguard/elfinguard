package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	gethcmn "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/elfinguard/elfinguard/types"
)

type Web3Client interface {
	HeaderByNumber(ctx context.Context, number *big.Int) (*ethtypes.Header, error)
	BlockNumber(ctx context.Context) (uint64, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]ethtypes.Log, error)
	TransactionByHash(ctx context.Context, hash gethcmn.Hash) (tx *ethtypes.Transaction, isPending bool, err error)
	TransactionReceipt(ctx context.Context, txHash gethcmn.Hash) (*ethtypes.Receipt, error)
	Close()
}

type DialContextFunc func(ctx context.Context, rawurl string) (Web3Client, error)
type AddressCheckFunc func(address gethcmn.Address, list []gethcmn.Address) bool

// var dialContext DialContextFunc = ethDialContext

func ethDialContext(ctx context.Context, rawurl string) (Web3Client, error) {
	return ethclient.DialContext(ctx, rawurl)
}

type rpcClient struct {
	dialContext           DialContextFunc
	addressCheckFunc      AddressCheckFunc
	requiredConfirmations int
	totalRpcTimeoutTime   time.Duration
}

// query an RPC server to fetch information and fill types.TxInfo
func (c *rpcClient) getTxInfo(rpcUrl string, txHash gethcmn.Hash) ([]byte, error) {
	ctx, cancelFn := context.WithTimeout(context.Background(), c.totalRpcTimeoutTime)
	defer cancelFn()

	client, err := c.dialContext(ctx, rpcUrl)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	receipt, err := client.TransactionReceipt(ctx, txHash)
	if err != nil {
		return nil, err
	}

	tx, _, err := client.TransactionByHash(ctx, txHash)
	if err != nil {
		return nil, err
	}

	// check isInAddressList
	if !c.addressCheckFunc(*tx.To(), AllowedToAccounts) {
		return nil, errors.New("to account not found in provided json file")
	}

	// from, err := ethtypes.NewEIP155Signer(ChainId).Sender(tx)
	from, err := ethtypes.NewLondonSigner(ChainId).Sender(tx)
	if err != nil {
		return nil, err
	}

	if receipt.Status != ethtypes.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("failed transaction: %s", txHash.Hex())
	}

	lastBlock, err := client.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}

	confirmations := int(lastBlock) - int(receipt.BlockNumber.Uint64())
	if confirmations < c.requiredConfirmations {
		return nil, fmt.Errorf("confirming: %d of %d", confirmations, c.requiredConfirmations)
	}

	header, err := client.HeaderByNumber(ctx, receipt.BlockNumber)
	if err != nil {
		return nil, err
	}

	txInfo := &types.TxInfo{
		ChainId:   ChainId,
		TxHash:    tx.Hash(),
		Timestamp: big.NewInt(int64(header.Time)),
		From:      from,
		To:        *tx.To(),
		Value:     tx.Value(),
		Data:      tx.Data(),
	}
	return txInfo.ToBytes(), nil
}

// query an RPC server to fetch information and fill types.LogInfo
func (c *rpcClient) getLogInfo(rpcUrl string, blockHash gethcmn.Hash,
	sourceContract gethcmn.Address, topics []gethcmn.Hash) ([]byte, error) {

	ctx, cancelFn := context.WithTimeout(context.Background(), c.totalRpcTimeoutTime)
	defer cancelFn()

	client, err := c.dialContext(ctx, rpcUrl)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	query := ethereum.FilterQuery{
		BlockHash: &blockHash,
		Addresses: []gethcmn.Address{sourceContract},
	}
	for _, t := range topics {
		query.Topics = append(query.Topics, []gethcmn.Hash{t})
	}

	logs, err := client.FilterLogs(ctx, query)
	if err != nil {
		return nil, err
	} else if len(logs) == 0 {
		return nil, errors.New("found no log")
	} else if len(logs) > 1 {
		return nil, errors.New("got more than one log")
	}

	log := logs[0]

	lastBlock, err := client.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}

	confirmations := int(lastBlock) - int(log.BlockNumber)
	if confirmations < c.requiredConfirmations {
		return nil, fmt.Errorf("confirming: %d of %d", confirmations, c.requiredConfirmations)
	}

	header, err := client.HeaderByNumber(ctx, big.NewInt(int64(log.BlockNumber)))
	if err != nil {
		return nil, err
	}

	logInfo := &types.LogInfo{
		ChainId:   ChainId,
		Timestamp: big.NewInt(int64(header.Time)),
		Address:   log.Address,
		Topics:    log.Topics,
		Data:      log.Data,
	}
	return logInfo.ToBytes(), nil
}

// Get a contract function's output using eth_call
func (c *rpcClient) getEthCallInfo(rpcUrl string, contractAddr, fromAddr gethcmn.Address, callData []byte) ([]byte, error) {
	//fmt.Println(rpcUrl)
	ctx, cancelFn := context.WithTimeout(context.Background(), c.totalRpcTimeoutTime)
	defer cancelFn()

	client, err := c.dialContext(ctx, rpcUrl)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	msg := ethereum.CallMsg{
		From:     fromAddr,
		To:       &contractAddr,
		GasPrice: big.NewInt(1),
		Value:    big.NewInt(0),
		Data:     callData,
	}

	lastBlock, err := client.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}

	header, err := client.HeaderByNumber(ctx, big.NewInt(int64(lastBlock)-int64(c.requiredConfirmations)))
	if err != nil {
		return nil, err
	}

	out, err := client.CallContract(ctx, msg, header.Number)
	if err != nil {
		return nil, err
	}

	ethCallInfo := &types.EthCallInfo{
		ChainId:   ChainId,
		Timestamp: big.NewInt(int64(header.Time)),
		From:      fromAddr,
		To:        contractAddr,
		OutData:   out,
	}
	copy(ethCallInfo.FunctionSelector[:], callData)
	return ethCallInfo.ToBytes(), nil
}

// Get a contract function's output using eth_call
func (c *rpcClient) ethCallForGrantCode(rpcUrl string, contractAddr, fromAddr gethcmn.Address, callData []byte) ([]byte, error) {
	//fmt.Println(rpcUrl)
	ctx, cancelFn := context.WithTimeout(context.Background(), c.totalRpcTimeoutTime)
	defer cancelFn()

	client, err := c.dialContext(ctx, rpcUrl)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	msg := ethereum.CallMsg{
		From:     fromAddr,
		To:       &contractAddr,
		GasPrice: big.NewInt(1),
		Value:    big.NewInt(0),
		Data:     callData,
	}

	lastBlock, err := client.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.CallContract(ctx, msg, big.NewInt(int64(lastBlock)-int64(c.requiredConfirmations)))
	return out, err
}
