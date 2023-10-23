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

	gethcmn "github.com/ethereum/go-ethereum/common"
)

func genSessionID(hmacKey []byte, sender gethcmn.Address) ([]byte, error) {
	var resultBz [48]byte
	copy(resultBz[:20], sender.Bytes())
	_, err := rand.Read(resultBz[20:28])
	if err != nil {
		return nil, fmt.Errorf("read rand err: %w", err)
	}

	binary.LittleEndian.PutUint32(resultBz[28:32], uint32(time.Now().Unix())) // timestamp
	hash := hmac.New(sha256.New, hmacKey)
	sum := hash.Sum(resultBz[:32])
	copy(resultBz[32:], sum)
	return resultBz[:], nil
}

func validateSessionID(sessionID, hmacKey []byte, maxSessionDuration int) error {
	if len(sessionID) != 48 {
		return errors.New("session length must be 48 bytes")
	}

	hash := hmac.New(sha256.New, hmacKey)
	temp := make([]byte, len(sessionID))
	copy(temp[:], sessionID)
	sum := hash.Sum(temp[:16])
	if !bytes.Equal(sessionID[32:], sum[:16]) { // check hmac signature
		return errors.New("invalid session id")
	}

	sessionTimestamp := binary.LittleEndian.Uint32(sessionID[28:32])
	if int64(sessionTimestamp+uint32(maxSessionDuration)) < time.Now().Unix() { // check timestamp
		return errors.New("session id is expired")
	}

	return nil
}
