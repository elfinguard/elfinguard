package request

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	gethcmn "github.com/ethereum/go-ethereum/common"

	"github.com/elfinguard/elfinguard/types"
)

type WsRequest struct {
	Op     string      `json:"op" binding:"required"`
	Params interface{} `json:"params"`
}

type WsEncryptMessageReq struct {
	Op     string           `json:"op" binding:"required"`
	Params EncryptParameter `json:"params" binding:"required"`
}

type EncryptParameter struct {
	Token  string `json:"token" binding:"required"`
	Origin string `json:"origin" binding:"required"`

	// parsed parameters
	OriginBz         []byte
	DecryptTaskToken types.DecryptTaskToken
}

func (req *WsEncryptMessageReq) Bind(message []byte) error {
	err := json.Unmarshal(message, req)
	if err != nil {
		return err
	}

	token, _, err := readBase58Token(req.Params.Token, false)
	if err != nil {
		return err
	}

	var ok bool
	req.Params.DecryptTaskToken, ok = token.(types.DecryptTaskToken)
	if !ok {
		return errors.New("invalid decrypt task token")
	}

	req.Params.OriginBz, err = base64.StdEncoding.DecodeString(req.Params.Origin)
	if err != nil {
		return err
	}

	return nil
}

type WsDecryptMessageReq struct {
	Op     string           `json:"op"`
	Params DecryptParameter `json:"params"`
}

type DecryptParameter struct {
	Nonce     string `json:"nonce" binding:"required"`
	Encrypted string `json:"encrypted" binding:"required"`
	Token     string `json:"token" binding:"required"`

	// parsed parameters
	NonceBz          []byte
	EncryptedBz      []byte
	DecryptTaskToken types.DecryptTaskToken
}

func (req *WsDecryptMessageReq) Bind(message []byte) error {
	err := json.Unmarshal(message, req)
	if err != nil {
		return err
	}

	token, _, err := readBase58Token(req.Params.Token, false)
	if err != nil {
		return err
	}

	var ok bool
	req.Params.DecryptTaskToken, ok = token.(types.DecryptTaskToken)
	if !ok {
		return errors.New("invalid decrypt task token")
	}

	req.Params.NonceBz = gethcmn.FromHex(req.Params.Nonce)
	req.Params.EncryptedBz, err = base64.StdEncoding.DecodeString(req.Params.Encrypted)
	if err != nil {
		return err
	}

	return nil
}
