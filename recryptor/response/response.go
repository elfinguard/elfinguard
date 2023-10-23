package response

type GetEncryptTaskTokenResp struct {
	EncryptTaskToken string `json:"encrypt_task_token"`
	Recryptorsalt    string `json:"recryptorsalt"`
	Pubkey           string `json:"pubkey"`
}

type GetDecryptTaskTokenResp struct {
	DecryptTaskToken string `json:"decrypt_task_token"`
	Pubkey           string `json:"pubkey"`
}
