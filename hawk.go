package hawk

import (
	//"crypto"
	//_ "crypto/sha256"
	sha "crypto/sha256"
	//_ "crypto/sha512"
	b64 "encoding/base64"
	"fmt"
	"math/rand"
	"time"
	"unsafe"
)

type RequestDetails struct {
	Protocol    string
	Host        string
	Port        uint
	URI         string
	Method      string
	ContentType string
	Data        []byte
	Ext         string
}

// Constants for nonce creation
const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var randSrc = rand.NewSource(time.Now().UnixNano())

// NewNonce creates a new n-length nonce.
func NewNonce(n int) string {
	// András Belicza
	// https://stackoverflow.com/a/31832326
	b := make([]byte, n)
	for i, cache, remain := n-1, randSrc.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSrc.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return *(*string)(unsafe.Pointer(&b))
}

func NewMAC(r RequestDetails) string {
	pl := fmt.Sprintf(
		"hawk.1.payload\n%s\n%x\n",
		r.ContentType, r.Data)

	pl_hash := sha.Sum256([]byte(pl))
	pl_b64 := b64.StdEncoding.EncodeToString(pl_hash[:])

	ts := time.Now().Unix()
	nonce := NewNonce(6)

	hdr := fmt.Sprintf(
		"hawk.1.header\n%d\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n",
		ts, nonce, r.Method, r.URI, r.Host, r.Port, pl_b64, r.Ext)

	hdr_hash := sha.Sum256([]byte(hdr))
	mac := b64.StdEncoding.EncodeToString(hdr_hash[:])

	return mac
}
