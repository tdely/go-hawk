// Package hawk provides a quick and easy way to send HTTP requests with
// Hawk authentication.
//
// Easiest is to use the provided client:
//
//     import (
//         "crypto"
//         hawk "gitlab.com/tdely/go-hawk"
//         "net/http"
//         "io"
//         "strings"
//         "time"
//     )
//
//     c := &http.Client{}
//     hc := hawk.NewClient("Hawk ID", []byte("secret"), crypto.SHA256, 6)
//     body := io.Reader(strings.NewReader("Hello world!"))
//     req, err := hc.NewRequest("POST", "https://example.com/greeting", body, "text/plain", "")
//     resp, err := c.Do(req)
//
// But if you want to not do payload verification or want to make life harder:
//
//     c := &http.Client{}
//     body := io.Reader(strings.NewReader("Hello world!"))
//     req, _ := http.NewRequest("POST", "https://example.com/greeting", body)
//     hd := HawkDetails{
//         Algorithm:   crypto.SHA256
//         Host:        "example.com",
//         Port:        "443",
//         URI:         "/greeting",
//         ContentType: "plain/text",
//         Content:     []byte("Hello world!"),
//         Method:      "POST"}
//     hd.Timestamp = time.Now().Unix()
//     hd.Nonce = NewNonce(6)
//     h, _ hd.Create()
//     // h.Validate()
//     h.Finalize("secret")
//     auth := h.GetAuthorization("Hawk ID")
//     req.Header.Add("Content-Type", "plain/text")
//     req.Header.Add("Authorization", auth)
//     resp, err := c.Do(req)
package hawk

import (
	"crypto"
	"crypto/hmac"
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

type Hawk struct {
	algorithm crypto.Hash

	host      string
	port      string
	uri       string
	method    string
	timestamp int64
	nonce     string

	reqContentType string
	reqContent     []byte
	reqExt         string
	reqHash        string
	reqMAC         string

	respContentType string
	respContent     []byte
	respExt         string
	respHash        string
	respMac         string
}

// Create takes the data in HawkDetails and creates a Hawk instance.
// Nonce and/or Timestamp may be omitted from HawkDetails to automatically
// create these values. Error on missing Host, Port, URI, Method, or Algorithm.
func (hd *HawkDetails) Create() (Hawk, error) {
	if !hd.Algorithm.Available() {
		fmt.Errorf("No algorithm provided")
	} else if hd.Host == "" {
		fmt.Errorf("No host provided")
	} else if hd.Port == "" {
		fmt.Errorf("No port provided")
	} else if hd.URI == "" {
		fmt.Errorf("No URI provided")
	} else if hd.Method == "" {
		fmt.Errorf("No method provided")
	}
	h := Hawk{
		algorithm:      hd.Algorithm,
		host:           hd.Host,
		port:           hd.Port,
		uri:            hd.URI,
		method:         hd.Method,
		timestamp:      hd.Timestamp,
		nonce:          hd.Nonce,
		reqContentType: hd.ContentType,
		reqContent:     hd.Content,
		reqExt:         hd.Ext}
	if h.nonce == "" {
		h.nonce = NewNonce(6)
	}
	if h.timestamp == 0 {
		h.timestamp = time.Now().Unix()
	}
	return h, nil
}

// HawkDetails is the data required for creating Authorization HTTP header for
// Hawk.
type HawkDetails struct {
	Algorithm   crypto.Hash
	Host        string
	Port        string
	URI         string
	ContentType string
	Content     []byte
	Method      string
	Timestamp   int64
	Nonce       string
	Ext         string
}

// Client is for creating HTTP requests that are automatically set up
// for Hawk authentication.
type Client struct {
	uid         string
	key         []byte
	hash        crypto.Hash
	NonceLength int
}

// Regexp pattern for capturing HTTP/HTTPS URLs
// Subgroups: 1 scheme, 2 host, 4 port, 5 URI
const urlPattern = "^(http|https)://([^:/]+)(:([0-9]+))?(/(.+)?)?$"

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
	// Author: András Belicza (icza)
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

func hashPayload(h crypto.Hash, ct string, c []byte) string {
	pl := fmt.Sprintf(
		"hawk.1.payload\n%s\n%s\n",
		ct, c)
	hasher := h.New()
	hasher.Write([]byte(pl))
	plHash := hasher.Sum(nil)
	return b64.StdEncoding.EncodeToString(plHash[:])
}

// Validate calculates and sets hash for Hawk request payload validation.
// Use before calling Finalize if payload validation is required.
func (h *Hawk) Validate() bool {
	if h.reqMAC != "" || h.reqContentType == "" {
		return false
	}
	h.reqHash = hashPayload(h.algorithm, h.reqContentType, h.reqContent)
	return true
}

func hashMAC(h crypto.Hash, k []byte, ts int64, n string, mtd string, uri string, hst string, p string, hsh string, ext string) string {
	hdr := []byte(fmt.Sprintf(
		"hawk.1.header\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
		ts, n, mtd, uri, hst, p, hsh, ext))
	m := hmac.New(h.New, k)
	m.Write(hdr)
	mac := m.Sum(nil)
	return b64.StdEncoding.EncodeToString(mac[:])
}

// Finalize calculates and sets Hawk message authentication code (MAC).
func (h *Hawk) Finalize(key []byte) bool {
	if h.timestamp == 0 || h.nonce == "" || h.method == "" || h.uri == "" || h.host == "" || h.port == "" || h.reqMAC != "" {
		return false
	}
	h.reqMAC = hashMAC(h.algorithm, key, h.timestamp, h.nonce, h.method, h.uri, h.host, h.port, h.reqHash, h.reqExt)
	return true
}

// GetReqMAC returns the Hawk request MAC.
func (h *Hawk) GetReqMAC() string {
	return h.reqMAC
}

// GetReqHash returns the Hawk request payload hash.
func (h *Hawk) GetReqHash() string {
	return h.reqHash
}

// GetAuthorization returns string to use in the Authorization HTTP header.
// An empty string will be returned if Finalize has not been used prior.
func (h *Hawk) GetAuthorization(uid string) string {
	if h.reqMAC == "" {
		return ""
	}
	hc := fmt.Sprintf(`Hawk id="%s", ts="%d", nonce="%s"`, uid, h.timestamp, h.nonce)
	if h.reqHash != "" {
		hc = fmt.Sprintf(`%s, hash="%s"`, hc, h.reqHash)
	}
	if h.reqExt != "" {
		hc = fmt.Sprintf(`%s, ext="%s"`, hc, h.reqExt)
	}
	hc = fmt.Sprintf(`%s, mac="%s"`, hc, h.reqMAC)
	return hc
}

// NewRequest creates a new HTTP request with preset Content-Type header and
// Authorization header for Hawk.
func (c *Client) NewRequest(method string, url string, body io.Reader, contentType string, ext string) (*http.Request, error) {
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
	}

	ts := time.Now().Unix()
	nonce := NewNonce(c.NonceLength)
	var content []byte
	if body != nil {
		content, _ = ioutil.ReadAll(body)
	}

	hd := HawkDetails{
		Algorithm:   c.hash,
		Host:        string(pURL[2]),
		Port:        port,
		URI:         string(pURL[5]),
		ContentType: contentType,
		Content:     content,
		Method:      method,
		Timestamp:   ts,
		Nonce:       nonce,
		Ext:         ext}
	h, _ := hd.Create()
	h.Validate()
	h.Finalize(c.key)
	auth := h.GetAuthorization(c.uid)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Authorization", auth)
	return req, nil
}

// NewClient creates a new Hawk client.
func NewClient(uid string, key []byte, algorithm crypto.Hash, nonceLength int) Client {
	if !algorithm.Available() {
		fmt.Errorf("No algorithm provided or algorithm unavailable")
	}
	return Client{uid: uid, key: key, hash: algorithm, NonceLength: nonceLength}
}
