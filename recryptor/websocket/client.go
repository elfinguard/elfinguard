package websocket

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/elfinguard/elfinguard/recryptor/constants"
	"github.com/elfinguard/elfinguard/recryptor/request"
	"github.com/elfinguard/elfinguard/recryptor/response"
	"github.com/elfinguard/elfinguard/types"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 2048
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte

	ip string
}

// readPump pumps messages from the websocket connection to the hub.
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Errorf("websocket read error: %v", err)
			}
			break
		}

		err = c.handleWsMessage(message, c.ip)
		if err != nil {
			log.Errorf("handle ws request error: %v", err)
		}
	}
}

func (c *Client) handleWsMessage(message []byte, ip string) error {
	var respBz []byte
	var err error

	var wsReq request.WsRequest
	err = json.Unmarshal(message, &wsReq)
	if err != nil {
		log.Errorf("unmarshal ws request error: %v", err)
		return err
	}

	switch wsReq.Op {
	case constants.WsPing:
		wsResponse := &response.WsPingResponse{Op: constants.WsPing, Results: response.PingResult{Message: "pong"}}
		respBz, _ = json.Marshal(wsResponse)
		c.send <- respBz

	case constants.WsEncryptMessage:
		wsResponse := &response.WsEncryptMessageResponse{}

		req := &request.WsEncryptMessageReq{}
		err := req.Bind(message)
		wsResponse.Op = constants.WsEncryptMessage

		if err != nil {
			wsResponse.Results.ErrorInfo = err.Error()
			respBz, _ = json.Marshal(wsResponse)
			c.send <- respBz
			return err
		}

		if req.Params.DecryptTaskToken.RemoteAddr != ip {
			err := errors.New("invalid ip address for this token")
			wsResponse.Results.ErrorInfo = err.Error()
			respBz, _ = json.Marshal(wsResponse)
			c.send <- respBz
			return err
		}

		encryptedBz, nonceBz, err := types.EncryptMessageWithNewNonce(req.Params.DecryptTaskToken, req.Params.OriginBz)
		if err != nil {
			wsResponse.Results.ErrorInfo = err.Error()
			respBz, _ = json.Marshal(wsResponse)
			c.send <- respBz
			return err
		}

		wsResponse.Results.Encrypted = base64.StdEncoding.EncodeToString(encryptedBz)
		wsResponse.Results.Nonce = gethcmn.Bytes2Hex(nonceBz)
		respBz, _ = json.Marshal(wsResponse)
		c.send <- respBz

	case constants.WsDecryptMessage:
		wsResponse := &response.WsDecryptMessageResponse{}

		req := &request.WsDecryptMessageReq{}
		err := req.Bind(message)
		wsResponse.Op = constants.WsDecryptMessage

		if err != nil {
			wsResponse.Results.ErrorInfo = err.Error()
			respBz, _ = json.Marshal(wsResponse)
			c.send <- respBz
			return err
		}

		if req.Params.DecryptTaskToken.RemoteAddr != ip {
			err := errors.New("invalid ip address for this token")
			wsResponse.Results.ErrorInfo = err.Error()
			respBz, _ = json.Marshal(wsResponse)
			c.send <- respBz
			return err
		}

		originBz, err := types.DecryptMessageWithNonce(req.Params.DecryptTaskToken, req.Params.EncryptedBz, req.Params.NonceBz)
		if err != nil {
			wsResponse.Results.ErrorInfo = err.Error()
			respBz, _ = json.Marshal(wsResponse)
			c.send <- respBz
			return err
		}

		wsResponse.Results.Origin = base64.StdEncoding.EncodeToString(originBz)
		respBz, _ = json.Marshal(wsResponse)
		c.send <- respBz

	default:
		return fmt.Errorf("unknown op %v", wsReq.Op)
	}

	return nil
}

// writePump pumps messages from the hub to the websocket connection.
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				log.Errorf("ws writer close error: %v", err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// serveWs handles websocket requests from the peer.
func ServeWs(hub *Hub, c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client
	client.ip = c.ClientIP()

	// Allow collection of memory referenced by the caller by doing all work in new goroutines.
	go client.writePump()
	go client.readPump()

	welcomeBz, _ := json.Marshal(map[string]interface{}{
		"op":      constants.WsOpen,
		"results": response.PingResult{Message: "welcome"},
	})
	client.send <- welcomeBz
}
