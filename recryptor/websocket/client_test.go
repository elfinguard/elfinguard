package websocket

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/elfinguard/elfinguard/recryptor/request"
	"github.com/elfinguard/elfinguard/recryptor/response"
	"github.com/elfinguard/elfinguard/types"
	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
)

var token = types.DecryptTaskToken{
	ExpireTime:    time.Now().Unix() + 100,
	FileId:        [32]byte{1},
	RecryptorSalt: [32]byte{1},
	Secret:        [32]byte{1},
	RemoteAddr:    "127.0.0.1",
	ViewerAccount: [20]byte{1},
	Contract:      "test",
}

func SetupWsRouter() *gin.Engine {
	hub := NewHub()
	go hub.Run()

	// Create test server with the echo handler.
	router := gin.Default()
	router.GET("/ws", func(c *gin.Context) {
		ServeWs(hub, c)
	})

	return router
}

func TestWsPing(t *testing.T) {
	router := SetupWsRouter()
	s := httptest.NewServer(router)
	defer s.Close()

	wsUrl := fmt.Sprintf("%v/ws", "ws"+strings.TrimPrefix(s.URL, "http"))
	ws, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	defer ws.Close()
	require.NoError(t, err)

	pingBz, _ := json.Marshal(map[string]interface{}{
		"op": "ping",
	})

	err = ws.WriteMessage(websocket.TextMessage, pingBz)
	require.NoError(t, err)

	_, welcomeBz, err := ws.ReadMessage()
	require.NoError(t, err)

	expectedWelcome, _ := json.Marshal(map[string]interface{}{
		"op":      "open",
		"results": response.PingResult{Message: "welcome"},
	})
	require.EqualValues(t, expectedWelcome, welcomeBz)

	_, pongBz, err := ws.ReadMessage()
	require.NoError(t, err)

	expectedPong, _ := json.Marshal(map[string]interface{}{
		"op":      "ping",
		"results": response.PingResult{Message: "pong"},
	})
	require.EqualValues(t, expectedPong, pongBz)
}

func TestWsDecryptMessage(t *testing.T) {
	router := SetupWsRouter()
	s := httptest.NewServer(router)
	defer s.Close()

	wsUrl := fmt.Sprintf("%v/ws", "ws"+strings.TrimPrefix(s.URL, "http"))
	ws, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	defer ws.Close()
	require.NoError(t, err)

	encrypted, nonce, _ := types.EncryptMessageWithNewNonce(token, []byte("test"))
	tokenBz, _ := token.MarshalMsg(nil)
	SealedToken, err := ecrypto.SealWithUniqueKey(tokenBz, nil)
	if err != nil {
		return
	}
	Base58EncodedToken := base58.Encode(SealedToken)
	if err != nil {
		return
	}

	decrypted, _ := json.Marshal(map[string]interface{}{
		"op":     "decryptMessage",
		"params": request.DecryptParameter{Nonce: gethcmn.Bytes2Hex(nonce), Encrypted: base64.StdEncoding.EncodeToString(encrypted), Token: Base58EncodedToken},
	})

	err = ws.WriteMessage(websocket.TextMessage, decrypted)
	require.NoError(t, err)

	_, welcomeBz, err := ws.ReadMessage()
	require.NoError(t, err)

	expectedWelcome, _ := json.Marshal(map[string]interface{}{
		"op":      "open",
		"results": response.PingResult{Message: "welcome"},
	})
	require.EqualValues(t, expectedWelcome, welcomeBz)

	_, decryptedMessage, err := ws.ReadMessage()
	require.NoError(t, err)

	expected, _ := json.Marshal(map[string]interface{}{
		"op":      "decryptMessage",
		"results": response.WsDecryptMessageResult{Origin: base64.StdEncoding.EncodeToString([]byte("test"))},
	})
	require.EqualValues(t, expected, decryptedMessage)
}
