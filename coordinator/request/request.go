package request

import (
	"errors"
	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

type GetSessionIDReq struct {
	// query parameters
	Sig   string `form:"sig" binding:"required"`
	Nonce string `form:"nonce" binding:"required"`

	// parsed parameters
	SigBz   []byte
	NonceBz []byte
}

func (req *GetSessionIDReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	req.SigBz = gethcmn.FromHex(req.Sig)
	req.NonceBz = gethcmn.FromHex(req.Nonce)

	err = validateSigBz(req.SigBz)
	if err != nil {
		return err
	}

	return nil
}

type GetRecryptorOrAuthorizerReq struct {
	SessionID string `form:"session" binding:"required"`

	// parsed parameters
	SessionBz []byte
}

func (req *GetRecryptorOrAuthorizerReq) Bind(c *gin.Context) error {
	// read query parameters
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	req.SessionBz = gethcmn.FromHex(req.SessionID)
	return nil
}

type GetFileReq struct {
	Path      string `form:"path" binding:"required"`
	SessionID string `form:"session" binding:"required"`

	// parsed parameters
	SessionBz []byte
}

func (req *GetFileReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	req.SessionBz = gethcmn.FromHex(req.SessionID)
	return nil
}

type UploadFileReq struct {
	// query parameters
	SessionID string `form:"session" binding:"required"`
	Recryptor string `form:"recryptor" binding:"required"`

	// parsed parameters
	SessionBz []byte
}

func (req *UploadFileReq) Bind(c *gin.Context) error {
	err := c.ShouldBindQuery(req)
	if err != nil {
		return err
	}

	req.SessionBz = gethcmn.FromHex(req.SessionID)
	return nil
}

// ----------------------------------------------------------------

func validateSigBz(sigBz []byte) error {
	if len(sigBz) != 65 {
		return errors.New("signature length must be 65")
	}
	if sigBz[64] > 1 {
		return errors.New("signature v must be 0 or 1")
	}
	return nil
}
