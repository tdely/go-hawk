package hawk

import (
	"crypto/hmac"
	sha "crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"time"
	"unsafe"
)

type RequestDetails struct {
	Host        string
	Port        string
	URI         string
	ContentType string
	Data        []byte
	Method      string
	Timestamp   int64
	Nonce       string
	Ext         string
	Hash        string
	MAC         string
}

type Hawk struct {
	client http.Client
	uid    string
	key    []byte
}

// Regexp pattern for capturing HTTP/HTTPS URLs
// Subgroups: 1 scheme, 2 host, 4 port, 5 URI
const urlPattern = "^(http|https)://([^:/]+)(:([0-9]+))?(/(.+)?)?"

// Constants for nonce creation
const (
	letterBytes   = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
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

// SetPayloadHash calculates and sets Hawk payload hash for request payload
// verification. Use before calling SetMAC if payload verification is required.
func (rd *RequestDetails) SetPayloadHash() {
	if rd.MAC != "" {
		return
	}
	pl := fmt.Sprintf(
		"hawk.1.payload\n%s\n%x\n",
		rd.ContentType, rd.Data)
	plHash := sha.Sum256([]byte(pl))
	rd.Hash = b64.StdEncoding.EncodeToString(plHash[:])
}

// SetMAC calculates and sets Hawk message authentication code (MAC).
func (rd *RequestDetails) SetMAC(key []byte) {
	hdr := []byte(fmt.Sprintf(
		"hawk.1.header\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
		rd.Timestamp, rd.Nonce, rd.Method, rd.URI, rd.Host, rd.Port, rd.Hash, rd.Ext))
	mac := hmac.New(sha.New, key)
	mac.Write(hdr)
	hashMAC := mac.Sum(nil)
	rd.MAC = b64.StdEncoding.EncodeToString(hashMAC[:])
}

// GetAuthorization returns string to use in the Authorization HTTP header.
func (rd *RequestDetails) GetAuthorization(uid string) string {
	return fmt.Sprintf(
		`Hawk id="%s", ts="%d", nonce="%s", mac="%s", hash="%s", ext="%s"`,
		uid, rd.Timestamp, rd.Nonce, rd.MAC, rd.Hash, rd.Ext)
}

// NewRequest creates a new HTTP request with preset Content-Type header and
// Authorization header for Hawk.
func (h *Hawk) NewRequest(method string, url string, body io.Reader, ct string, ext string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return req, err
	}
	re := regexp.MustCompile(urlPattern)
	pURL := re.FindSubmatch([]byte(url))
	if len(pURL) == 0 {
		return nil, fmt.Errorf("Failed to parse URL: %s", url)
	}

	var port string
	if string(pURL[3]) != "" {
		port = string(pURL[4])
	} else if string(pURL[1]) == "https" {
		port = "443"
	} else if string(pURL[1]) == "http" {
		port = "80"
	} else {
		return nil, fmt.Errorf("Unsupported scheme: %s", string(pURL[1]))
	}

	ts := time.Now().Unix()
	nonce := NewNonce(6)
	sData, _ := ioutil.ReadAll(body)

	rd := RequestDetails{
		Host:        string(pURL[2]),
		Port:        port,
		URI:         string(pURL[5]),
		ContentType: ct,
		Data:        sData,
		Method:      method,
		Timestamp:   ts,
		Nonce:       nonce,
		Ext:         ext}
	rd.SetPayloadHash()
	rd.SetMAC(h.key)
	auth := rd.GetAuthorization(h.uid)
	req.Header.Add("Content-Type", ct)
	req.Header.Add("Authorization", auth)
	return req, nil
}

// New creates a new Hawk HTTP client.
func New(uid string, key []byte, client http.Client) Hawk {
	return Hawk{uid: uid, key: key, client: client}
}
