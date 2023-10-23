package util

import (
	"encoding/hex"
	"fmt"

	gethcmn "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func RecoverSender(sig, nonce []byte, coordinatorDomain string) (gethcmn.Address, error) {
	txt := fmt.Sprintf("Login %s with nonce: %s", coordinatorDomain, hex.EncodeToString(nonce))
	ethMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(txt), txt) //EIP191 prefix
	ethMsgHash := gethcrypto.Keccak256([]byte(ethMsg))
	pubkey, err := gethcrypto.SigToPub(ethMsgHash, sig)
	if err != nil {
		return gethcmn.Address{}, err
	}
	return gethcrypto.PubkeyToAddress(*pubkey), nil
}
