package constants

const (
	APIPing                    = "eg_ping"
	APIGetEncryptTaskToken     = "eg_getEncryptTaskToken"
	APIGetEncryptTaskTokenList = "eg_getEncryptTaskTokenList"
	APIGetEncryptedParts       = "eg_getEncryptedParts"
	APIEncryptChunk            = "eg_encryptChunk"
	APIEncryptChunkOnServer    = "eg_encryptChunkOnServer"
	APIGetDecryptTaskToken     = "eg_getDecryptTaskToken"
	APIDecryptChunk            = "eg_decryptChunk"
	APIGetDecryptedFile        = "eg_getDecryptedFile"
	APIPubkey                  = "pubkey"
	APIPubkeyReport            = "pubkey_report"
	APICert                    = "cert"
	APICertReport              = "cert_report"

	WsOpen           = "open"
	WsPing           = "ping"
	WsEncryptMessage = "encryptMessage"
	WsDecryptMessage = "decryptMessage"
)
