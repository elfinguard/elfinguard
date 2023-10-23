package main

import (
	"math/big"

	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestGetTxInfo(t *testing.T) {
	_rpcClient.dialContext = testDialContext // change global variable
	ChainId = big.NewInt(int64(10000))

	res, err := _rpcClient.getTxInfo(
		"",
		// 1,
		common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
	)

	require.NotEmpty(t, res)
	require.Nil(t, err)
}

func TestGetLogInfo(t *testing.T) {
	_rpcClient.dialContext = testDialContext
	ChainId = big.NewInt(int64(10000))

	res, err := _rpcClient.getLogInfo(
		"",
		// 1,
		common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
		common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		[]common.Hash{common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}},
	)

	require.NotEmpty(t, res)
	require.Nil(t, err)
}

func TestGetEthCallInfo(t *testing.T) {
	ChainId = big.NewInt(int64(10000))
	_rpcClient.dialContext = testDialContext
	res, err := _rpcClient.getEthCallInfo(
		"",
		common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	)

	require.NotEmpty(t, res)
	require.Nil(t, err)
}

func TestEthCallForGrantCode(t *testing.T) {
	_rpcClient.dialContext = testDialContext

	res, err := _rpcClient.ethCallForGrantCode(
		"rpcUrl1.com",
		common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
	)

	require.NotEmpty(t, res)
	require.Nil(t, err)
}
