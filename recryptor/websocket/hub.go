package websocket

import (
	log "github.com/sirupsen/logrus"
)

// Hub maintains the set of active clients
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client
}

func NewHub() *Hub {
	return &Hub{
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			log.Infof("client connects to ws server, ip: %v", client.ip)
			h.clients[client] = true

		case client := <-h.unregister:
			log.Infof("client disconnects to ws server, ip: %v", client.ip)

			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		}
	}
}
