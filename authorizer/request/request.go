package request

import (
	"errors"
	"fmt"
	"io"
	"strings"

	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

type GetKeysReq struct {
	// query parameters
	Keys string `form:"k" binding:"required"`

	// parsed parameters
	EncryptedPrivKeyBz []byte
	PeerPubKeyBz33     [33]byte
}

func (req *GetKeysReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	keysArr := strings.Split(req.Keys, ",")
	if len(keysArr) != 2 {
		return errors.New("length of keys is not 2")
	}

	pubKeyBz := gethcmn.FromHex(keysArr[0])
	err = validatePubKey(pubKeyBz)
	if err != nil {
		return errors.New("invalid peer public key")
	}

	copy(req.PeerPubKeyBz33[:], pubKeyBz)
	req.EncryptedPrivKeyBz = gethcmn.FromHex(keysArr[1])

	return nil
}

type GetTxReq struct {
	// query parameters
	TxHash string `form:"hash" binding:"required"`

	// parsed parameters
	TxCommonHash gethcmn.Hash
}

func (req *GetTxReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	txHashBz := gethcmn.FromHex(req.TxHash)
	err = validateHash(txHashBz)
	if err != nil {
		return errors.New("invalid tx hash")
	}

	copy(req.TxCommonHash[:], txHashBz)
	return nil
}

type GetLogReq struct {
	// query parameters
	BlockHash    string `form:"block" binding:"required"`
	ContractAddr string `form:"contract" binding:"required"`
	Topic0       string `form:"topic0"`
	Topic1       string `form:"topic1"`
	Topic2       string `form:"topic2"`
	Topic3       string `form:"topic3"`

	// parsed parameters
	BlockHashCmn    gethcmn.Hash
	ContractAddrCmn gethcmn.Address
	TopicsCmn       []gethcmn.Hash
}

func (req *GetLogReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	blockHashBz := gethcmn.FromHex(req.BlockHash)
	err = validateHash(blockHashBz)
	if err != nil {
		return errors.New("invalid block hash")
	}

	contractAddrBz := gethcmn.FromHex(req.ContractAddr)
	err = validateAddress(contractAddrBz)
	if err != nil {
		return errors.New("invalid contract address")
	}

	copy(req.BlockHashCmn[:], blockHashBz)
	copy(req.ContractAddrCmn[:], contractAddrBz)

	topicNum := 0
	for i := 0; i < 4; i++ {
		topicStr := req.GetTopic(i)
		if topicStr == "" {
			break
		}

		topicBz := gethcmn.FromHex(topicStr)
		err := validateHash(topicBz)
		if err != nil {
			return fmt.Errorf("invalid topic%d", i)
		}

		req.TopicsCmn = append(req.TopicsCmn, bytesToHash(topicBz))
		topicNum++
	}

	if topicNum == 0 {
		return errors.New("no topic in parameters")
	}

	return nil
}

func (req *GetLogReq) GetTopic(i int) string {
	switch i {
	case 0:
		return req.Topic0
	case 1:
		return req.Topic1
	case 2:
		return req.Topic2
	case 3:
		return req.Topic3
	}
	return ""
}

type GetCallReq struct {
	// query parameters
	ContractAddr string `form:"contract" binding:"required"`
	FromAddr     string `form:"from" binding:"required"`
	CallData     string `form:"data" binding:"required"`

	// parsed parameters
	ContractAddrCmn gethcmn.Address
	FromAddrCmn     gethcmn.Address
	CallDataBz      []byte
}

func (req *GetCallReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	contractAddrBz := gethcmn.FromHex(req.ContractAddr)
	err = validateAddress(contractAddrBz)
	if err != nil {
		return errors.New("invalid contract address")
	}

	fromAddrBz := gethcmn.FromHex(req.FromAddr)
	err = validateAddress(fromAddrBz)
	if err != nil {
		return errors.New("invalid from address")
	}

	copy(req.ContractAddrCmn[:], contractAddrBz)
	copy(req.FromAddrCmn[:], fromAddrBz)
	req.CallDataBz = gethcmn.FromHex(req.CallData)

	return nil
}

type GetGrantcodeReq struct {
	// query parameters
	ContractAddr    string `form:"contract" binding:"required"`
	CallDataList    string `form:"datalist" binding:"required"`
	Nth             int    `form:"nth"`
	Time            int64  `form:"time" binding:"required"`
	OutData         string `form:"out"`
	Sig             string `form:"sig"`
	RecryptorPubkey string `form:"recryptorpk" binding:"required"`

	// body
	ReportBz []byte

	// parsed parameters
	ContractAddrCmn   gethcmn.Address
	CallDataBzList    [][]byte
	OutDataBz         []byte
	SigBz             []byte
	RecryptorPubkeyBz []byte
}

func (req *GetGrantcodeReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	if req.Nth < 0 {
		return errors.New("invalid nth")
	}

	contractAddrBz := gethcmn.FromHex(req.ContractAddr)
	err = validateAddress(contractAddrBz)
	if err != nil {
		return errors.New("invalid contract address")
	}
	copy(req.ContractAddrCmn[:], contractAddrBz)

	req.ReportBz, err = io.ReadAll(c.Request.Body)
	if err != nil {
		return err
	}

	callDatas := strings.Split(req.CallDataList, ",")
	req.CallDataBzList = make([][]byte, 0, len(callDatas))
	for _, cd := range callDatas {
		cdBz := gethcmn.FromHex(cd)
		req.CallDataBzList = append(req.CallDataBzList, cdBz)
	}

	req.SigBz = gethcmn.FromHex(req.Sig)
	req.OutDataBz = gethcmn.FromHex(req.OutData)
	req.RecryptorPubkeyBz = gethcmn.FromHex(req.RecryptorPubkey)

	if len(req.SigBz) == 0 && len(req.OutDataBz) == 0 {
		return errors.New("sig and outData cannot be empty at the same time")
	}

	if len(req.SigBz) > 0 {
		err = validateSig(req.SigBz)
		if err != nil {
			return err
		}
	}

	err = validatePubKey(req.RecryptorPubkeyBz)
	if err != nil {
		return err
	}

	return nil
}

// ----------------------------------------------------------------

func bytesToHash(bz []byte) gethcmn.Hash {
	var hash gethcmn.Hash
	copy(hash[:], bz)
	return hash
}

func validateAddress(address []byte) error {
	if len(address) != 20 {
		return errors.New("invalid address")
	}
	return nil
}

func validateHash(hashBz []byte) error {
	if len(hashBz) != 32 {
		return errors.New("invalid hash")
	}
	return nil
}

func validatePubKey(pubKey []byte) error {
	if len(pubKey) != 33 {
		return errors.New("invalid public key")
	}
	return nil
}

func validateSig(sig []byte) error {
	if len(sig) != 65 {
		return errors.New("signature length must be 65")
	}
	if sig[64] > 1 {
		return errors.New("signature v must be 0 or 1")
	}
	return nil
}
