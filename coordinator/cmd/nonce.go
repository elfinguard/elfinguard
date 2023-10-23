package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

func genNonce(hmacKey []byte) ([]byte, error) {
	var bz [32]byte
	_, err := rand.Read(bz[:12])
	if err != nil {
		return nil, fmt.Errorf("read rand err: %w", err)
	}

	binary.LittleEndian.PutUint32(bz[12:16], uint32(time.Now().Unix()))
	hash := hmac.New(sha256.New, hmacKey)
	sum := hash.Sum(bz[:16])
	copy(bz[16:], sum)

	return bz[:], nil
}

func validateNonce(nonce, hmacKey []byte, duration int) error {
	if len(nonce) != 32 {
		return errors.New("nonce length must be 32 bytes")
	}

	hash := hmac.New(sha256.New, hmacKey)
	temp := make([]byte, len(nonce))
	copy(temp[:], nonce)

	// check hmac signature
	sum := hash.Sum(temp[:16])
	if !bytes.Equal(nonce[16:], sum[:16]) {
		return errors.New("invalid hmac signature")
	}

	// check timestamp
	nonceTimestamp := binary.LittleEndian.Uint32(nonce[12:16])
	if int64(nonceTimestamp+uint32(duration)) < time.Now().Unix() {
		return errors.New("nonce is expired")
	}

	return nil
}
