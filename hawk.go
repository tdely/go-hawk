// Package hawk provides a quick and easy way to send HTTP requests with
// Hawk authentication.
//
// Easiest is to use the provided client:
//
//     import (
//         "crypto"
//         hawk "gitlab.com/tdely/go-hawk"
//         "net/http"
//         "strings"
//     )
//
//     c := &http.Client{}
//     hc := hawk.NewClient("your-hawk-id", []byte("secret"), crypto.SHA256, 6)
//     body := strings.NewReader("Hello world!")
//     req, err := hc.NewRequest("POST", "https://example.com/greeting", body, "text/plain", "some-app-ext-data")
//     resp, err := c.Do(req)
//     // Check validity of response
//     valid := hc.ValidateResponse(*resp)
//
// But if you want to not do payload verification or want to make life harder:
//
//     import (
//         "crypto"
//         hawk "gitlab.com/tdely/go-hawk"
//         "net/http"
//         "strings"
//         "time"
//     )
//
//     c := &http.Client{}
//     body := strings.NewReader("Hello world!")
//     req, _ := http.NewRequest("POST", "https://example.com/greeting", body)
//     hd := hawk.Details{
//         Algorithm:   crypto.SHA256,
//         Host:        "example.com",
//         Port:        "443",
//         URI:         "/greeting",
//         ContentType: "plain/text",
//         Content:     []byte("Hello world!"),
//         Method:      "POST",
//         Ext:         "some-app-ext-data"}
//     hd.Timestamp = time.Now().Unix()
//     hd.Nonce = hawk.NewNonce(6)
//     h, _ := hd.Create()
//     // h.Validate()
//     h.Finalize([]("secret"))
//     auth := h.GetAuthorization("your-hawk-id")
//     req.Header.Add("Content-Type", "plain/text")
//     req.Header.Add("Authorization", auth)
//     resp, err := c.Do(req)
//     // valid := h.ValidateResponse([]byte("justtesting"), *resp)
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
	"strings"
	"time"
	"unsafe"
)

// Hawk is created from Details.Create() and used for creating the Hawk
// Authorization header.
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
	respMAC         string
}

// Create takes the data in Details and creates a Hawk instance.
// Nonce and/or Timestamp may be omitted from Details to automatically
// create these values. Error on missing Host, Port, URI, Method, or Algorithm.
func (hd *Details) Create() (Hawk, error) {
	var err error
	if !hd.Algorithm.Available() {
		err = fmt.Errorf("No algorithm provided")
	} else if hd.Host == "" {
		err = fmt.Errorf("No host provided")
	} else if hd.Port == "" {
		err = fmt.Errorf("No port provided")
	} else if hd.URI == "" {
		err = fmt.Errorf("No URI provided")
	} else if hd.Method == "" {
		err = fmt.Errorf("No method provided")
	}
	if err != nil {
		return Hawk{}, nil
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

// Details is the data required for creating Authorization HTTP header for
// Hawk.
type Details struct {
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
	hawk        Hawk
}

// Regexp pattern for capturing HTTP/HTTPS URLs
// Subgroups: 1 scheme, 2 host, 4 port, 5 URI
const urlPattern = "^(http|https)://([^:/]+)(:([0-9]+))?(/(.+)?)?$"

// Regexp pattern for capturing Hawk header elements.
const hawkPattern = `(\w+)="([^"]*)"`

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

// ValidateResponse validates the response to a Hawk request for message
// authenticity, and if hash is sent: payload verification.
func (h *Hawk) ValidateResponse(k []byte, r http.Response) bool {
	ct := r.Header.Get("Content-Type")
	if ct != "" && strings.Index(ct, ";") != -1 {
		h.respContentType = ct[:strings.Index(ct, ";")]
	} else if ct != "" {
		h.respContentType = ct
	}
	auth := r.Header.Get("Server-Authorization")
	re := regexp.MustCompile(hawkPattern)
	elements := re.FindAllSubmatch([]byte(auth), -1)
	for _, e := range elements {
		key := string(e[1])
		val := string(e[2])
		switch key {
		case "ext":
			h.respExt = val
		case "hash":
			h.respHash = val
		case "mac":
			h.respMAC = val
		}
	}
	if r.Body != nil {
		h.respContent, _ = ioutil.ReadAll(r.Body)
		r.Body.Close()
	}

	calcHash := hashPayload(h.algorithm, h.respContentType, h.respContent)
	if h.respHash != "" && h.respHash != calcHash {
		return false
	}
	calcMAC := hashMAC(h.algorithm, k, h.timestamp, h.nonce, h.method, h.uri, h.host, h.port, h.respHash, h.respExt)
	if h.respMAC != calcMAC {
		return false
	}
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
	if req.Body != nil {
		body, _ = req.GetBody()
		content, _ = ioutil.ReadAll(body)
	}

	hd := Details{
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
	c.hawk, _ = hd.Create()
	c.hawk.Validate()
	c.hawk.Finalize(c.key)
	auth := c.hawk.GetAuthorization(c.uid)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Authorization", auth)
	return req, nil
}

// ValidateResponse validates the response to a Hawk request for message
// authenticity, and if hash is sent: payload verification.
func (c *Client) ValidateResponse(r http.Response) bool {
	return c.hawk.ValidateResponse(c.key, r)
}

// NewClient creates a new Hawk client.
func NewClient(uid string, key []byte, algorithm crypto.Hash, nonceLength int) Client {
	return Client{uid: uid, key: key, hash: algorithm, NonceLength: nonceLength}
}
