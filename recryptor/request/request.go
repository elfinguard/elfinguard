package request

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/edgelesssys/ego/ecrypto"
	gethcmn "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/mr-tron/base58"

	"github.com/elfinguard/elfinguard/recryptor/constants"
	"github.com/elfinguard/elfinguard/types"
)

type GetEncryptTaskTokenReq struct {
	Sig    string `form:"sig" binding:"required"`
	FileId string `form:"fileId" binding:"required"`

	// parsed parameters
	SigBz            []byte
	EncryptTaskToken types.EncryptTaskToken
}

func (req *GetEncryptTaskTokenReq) Bind(c *gin.Context) error {
	// read query parameters
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	req.SigBz = gethcmn.FromHex(req.Sig)
	err = validateSig(req.SigBz)
	if err != nil {
		return err
	}

	req.EncryptTaskToken, err = generateEncryptTaskToken(req.FileId, req.SigBz)
	if err != nil {
		return err
	}

	return nil
}

type GetEncryptTaskTokenListReq struct {
	Sig     string `form:"sig" binding:"required"`
	FileIds string `form:"fileIds" binding:"required"`

	// parsed parameters
	SigBz                []byte
	EncryptTaskTokenList []types.EncryptTaskToken
}

func (req *GetEncryptTaskTokenListReq) Bind(c *gin.Context) error {
	// read query parameters
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	fileIdArray := strings.Split(req.FileIds, ",")
	if len(fileIdArray) == 0 || len(fileIdArray) > 100 {
		return fmt.Errorf("invalid amount of fileIds")
	}

	req.SigBz = gethcmn.FromHex(req.Sig)
	err = validateSig(req.SigBz)
	if err != nil {
		return err
	}

	req.EncryptTaskTokenList, err = generateEncryptTaskTokenList(req.FileIds, fileIdArray, req.SigBz)
	if err != nil {
		return err
	}

	return nil
}

type GetEncryptedPartsReq struct {
	// query params
	Token string

	// body
	ChainId        int64    `json:"chainid" binding:"required"`
	Contract       string   `json:"contract" binding:"required"`
	Function       string   `json:"function" binding:"required"`
	Threshold      int      `json:"threshold" binding:"required"`
	AuthorizerList []string `json:"authorizerlist" binding:"required"`
	OutData        []byte   `json:"outdata" binding:"required"`

	// parsed parameters
	EncryptTaskToken types.EncryptTaskToken
	TokenBzBase58    []byte
	EncryptionGuide  types.EncryptionGuide
}

func (req *GetEncryptedPartsReq) Bind(c *gin.Context) error {
	req.Token = c.Query("token")
	if req.Token == "" {
		return errors.New("invalid token")
	}

	err := c.ShouldBindJSON(req)
	if err != nil {
		return err
	}

	token, tokenBz, err := readBase58Token(req.Token, true)
	if err != nil {
		return err
	}

	req.EncryptTaskToken = token.(types.EncryptTaskToken)
	req.TokenBzBase58 = tokenBz
	req.EncryptionGuide = types.EncryptionGuide{
		ChainId:        big.NewInt(req.ChainId),
		Contract:       req.Contract,
		Function:       req.Function,
		Threshold:      req.Threshold,
		AuthorizerList: req.AuthorizerList,
		OutData:        req.OutData,
	}
	return nil
}

type EncryptOrDecryptChunkReq struct {
	IsEncrypt bool

	// query params
	Token string `form:"token" binding:"required"`
	Index int    `form:"index"`

	// body
	Chunk []byte

	// parsed parameters
	EncryptTaskToken types.EncryptTaskToken
	DecryptTaskToken types.DecryptTaskToken
	TokenBzBase58    []byte
}

func (req *EncryptOrDecryptChunkReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	if req.Index < 0 {
		return errors.New("invalid index")
	}

	req.Chunk, err = io.ReadAll(c.Request.Body)
	if len(req.Chunk) == 0 {
		return errors.New("body cannot be empty")
	}

	token, tokenBz, err := readBase58Token(req.Token, req.IsEncrypt)
	if err != nil {
		return err
	}

	if req.IsEncrypt {
		req.EncryptTaskToken = token.(types.EncryptTaskToken)
	} else {
		req.DecryptTaskToken = token.(types.DecryptTaskToken)
	}
	req.TokenBzBase58 = tokenBz
	return nil
}

type GetDecryptedPartsReq struct {
	ChainId        int64    `json:"chainid" binding:"required"`        // got from config.json of ElfinDirectory
	Contract       string   `json:"contract" binding:"required"`       // got from config.json of ElfinDirectory
	Function       string   `json:"function" binding:"required"`       // got from config.json of ElfinDirectory
	Threshold      int      `json:"threshold" binding:"required"`      // got from config.json of ElfinDirectory
	AuthorizerList []string `json:"authorizerlist" binding:"required"` // got from config.json of ElfinDirectory
	EncryptedParts [][]byte `json:"encryptedparts" binding:"required"` // generated by the Authorizers
	CallDataList   [][]byte `json:"calldatalist" binding:"required"`   // specified by the viewer
	Signature      []byte   `json:"signature" binding:"required"`      // signed by the viewer
	Timestamp      int64    `json:"timestamp" binding:"required"`      // specified by the viewer
	RecryptorSalt  []byte   `json:"recryptorsalt" binding:"required"`  // got from config.json of ElfinDirectory
	FileId         []byte   `json:"fileid" binding:"required"`         // got from config.json of ElfinDirectory

	// parsed parameters
	DecryptionGuide types.DecryptionGuide
}

func (req *GetDecryptedPartsReq) Bind(c *gin.Context) error {
	err := c.ShouldBindJSON(req)
	if err != nil {
		return err
	}

	req.DecryptionGuide = types.DecryptionGuide{
		ChainId:        big.NewInt(req.ChainId),
		Contract:       req.Contract,
		Function:       req.Function,
		Threshold:      req.Threshold,
		AuthorizerList: req.AuthorizerList,
		EncryptedParts: req.EncryptedParts,
		CallDataList:   req.CallDataList,
		Signature:      req.Signature,
		Timestamp:      req.Timestamp,
		RecryptorSalt:  req.RecryptorSalt,
		FileId:         req.FileId,
	}
	return nil
}

type GetDecryptedFileReq struct {
	// query params
	Token string `form:"token" binding:"required"`
	Path  string `form:"path" binding:"required"`
	Size  int    `form:"size" binding:"required"` // bytes, must be greater than 0

	// uri
	FileName string `uri:"file"`

	// parsed parameters
	DecryptTaskToken types.DecryptTaskToken
	TokenBzBase58    []byte
}

func (req *GetDecryptedFileReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	req.FileName = c.Param("file")
	if req.FileName == "" {
		return errors.New("file uri is empty")
	}

	token, tokenBz, err := readBase58Token(req.Token, false)
	if err != nil {
		return err
	}

	req.DecryptTaskToken = token.(types.DecryptTaskToken)
	req.TokenBzBase58 = tokenBz
	return nil
}

// ----------------------------------------------------------------

func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
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

func readBase58Token(tokenStr string, isEncryptTaskToken bool) (interface{}, []byte, error) {
	if has0xPrefix(tokenStr) {
		tokenStr = tokenStr[2:]
	}

	sealedTokenBz, err := base58.Decode(tokenStr)
	if err != nil {
		return nil, nil, fmt.Errorf("decode base58 string: %v", err)
	}

	tokenBz, err := ecrypto.Unseal(sealedTokenBz, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unseal token: %v", err)
	}

	// EncryptTaskToken
	if isEncryptTaskToken {
		var token types.EncryptTaskToken
		_, err = token.UnmarshalMsg(tokenBz)
		if err != nil {
			return nil, nil, fmt.Errorf("unmarshal encrypt task token: %v", err)
		}

		return token, tokenBz, nil
	}

	// DecryptTaskToken
	var token types.DecryptTaskToken
	_, err = token.UnmarshalMsg(tokenBz)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal decrypt task token: %v", err)
	}

	return token, tokenBz, nil
}

func generateEncryptTaskToken(fileId string, SigBz []byte) (token types.EncryptTaskToken, err error) {
	var fileIdBz32 [32]byte
	copy(fileIdBz32[:], gethcmn.FromHex(fileId))

	txt := fmt.Sprintf("To Recryptor: fileId=%s", hex.EncodeToString(fileIdBz32[:]))
	ethMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(txt), txt) //EIP191 prefix
	ethMsgHash := gethcrypto.Keccak256([]byte(ethMsg))
	pubkey, err := gethcrypto.SigToPub(ethMsgHash, SigBz)
	if err != nil {
		return token, err
	}

	token = types.EncryptTaskToken{
		ExpireTime:    time.Now().Unix() + constants.MaxDecryptionDuration,
		FileId:        fileIdBz32,
		RecryptorSalt: types.NewRandReader().Read32(),
		Secret:        types.NewRandReader().Read32(),
		RequestorAddr: gethcrypto.PubkeyToAddress(*pubkey),
	}
	return token, nil
}

func generateEncryptTaskTokenList(fileIds string, fileIdsArray []string, SigBz []byte) (tokens []types.EncryptTaskToken, err error) {
	txt := fmt.Sprintf("To Recryptor: fileIds=%s", fileIds)
	ethMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(txt), txt) //EIP191 prefix
	ethMsgHash := gethcrypto.Keccak256([]byte(ethMsg))
	pubkey, err := gethcrypto.SigToPub(ethMsgHash, SigBz)
	if err != nil {
		return tokens, err
	}

	tokens = make([]types.EncryptTaskToken, 0, len(fileIdsArray))
	now := time.Now().Unix()

	for _, fileIdStr := range fileIdsArray {
		var fileIdBz32 [32]byte
		copy(fileIdBz32[:], gethcmn.FromHex(fileIdStr))

		tokens = append(tokens, types.EncryptTaskToken{
			ExpireTime:    now + constants.MaxDecryptionDuration,
			FileId:        fileIdBz32,
			RecryptorSalt: types.NewRandReader().Read32(),
			Secret:        types.NewRandReader().Read32(),
			RequestorAddr: gethcrypto.PubkeyToAddress(*pubkey),
		})
	}

	return tokens, nil
}
