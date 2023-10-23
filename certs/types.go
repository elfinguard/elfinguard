package certs

type CSRData struct {
	CommonName         string `json:"commonName"`
	Country            string `json:"country"`
	Province           string `json:"province"`
	Locality           string `json:"locality"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	EmailAddress       string `json:"emailAddress"`
}
