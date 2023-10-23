package response

type PingResult struct {
	Message string `json:"message"`
}

type WsPingResponse struct {
	Op      string     `json:"op"`
	Results PingResult `json:"results"`
}

type WsEncryptMessageResult struct {
	ErrorInfo string `json:"error_info,omitempty"`
	Nonce     string `json:"nonce"`
	Encrypted string `json:"encrypted"`
}

type WsEncryptMessageResponse struct {
	Op      string                 `json:"op"`
	Results WsEncryptMessageResult `json:"results"`
}

type WsDecryptMessageResult struct {
	ErrorInfo string `json:"error_info,omitempty"`
	Origin    string `json:"origin"`
}

type WsDecryptMessageResponse struct {
	Op      string                 `json:"op"`
	Results WsDecryptMessageResult `json:"results"`
}

