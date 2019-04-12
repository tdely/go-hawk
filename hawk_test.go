package hawk

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestNonce(t *testing.T) {
	re := regexp.MustCompile("^[[:alnum:]]+$")
	t.Run("zero", func(t *testing.T) {
		n := 0
		match := re.Find([]byte(NewNonce(n)))
		if got, want := len(match), n; got != want {
			t.Errorf("NewNonce failed:\n  got match length: %d\n  want match length:  %d", got, want)
		}
	})
	t.Run("six", func(t *testing.T) {
		n := 6
		match := re.Find([]byte(NewNonce(n)))
		if got, want := len(match), n; got != want {
			t.Errorf("NewNonce failed:\n  got match length: %d\n  want match length:  %d", got, want)
		}
	})
	t.Run("repetition", func(t *testing.T) {
		n := 6
		mOne := re.Find([]byte(NewNonce(n)))
		mTwo := re.Find([]byte(NewNonce(n)))
		if bytes.Equal(mOne, mTwo) {
			t.Errorf("NewNonce failed: both results equal (%s == %s)", mOne, mTwo)
		}
	})
	t.Run("remain-zero", func(t *testing.T) {
		n := 11
		match := re.Find([]byte(NewNonce(n)))
		if got, want := len(match), n; got != want {
			t.Errorf("NewNonce failed:\n  got match length: %d\n  want match length:  %d", got, want)
		}
	})
}

func TestHawkSpecifics(t *testing.T) {
	t.Run("standard", func(t *testing.T) {
		hd := Details{
			Algorithm: crypto.SHA256,
			Host:      "example.com",
			Port:      "8000",
			URI:       "/resource/1?b=1&a=2",
			Method:    "GET",
			Timestamp: 1353832234,
			Nonce:     "j4h3g2",
			Ext:       "some-app-ext-data"}
		h, _ := hd.Create()
		h.Finalize([]byte("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"))
		if got, want := h.GetReqMAC(), "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="; got != want {
			t.Errorf("SetMAC failed:\n  want: %s\n  got:  %s", got, want)
		}
		if got, want := h.GetAuthorization("dh37fgj492je"), `Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="`; got != want {
			t.Errorf("GetAuthorization failed:\n  got:  %s\n  want: %s", got, want)
		}
	})
	t.Run("standard-payload", func(t *testing.T) {
		hd := Details{
			Algorithm:   crypto.SHA256,
			Host:        "example.com",
			Port:        "8000",
			URI:         "/resource/1?b=1&a=2",
			Method:      "POST",
			ContentType: "text/plain",
			Content:     []byte("Thank you for flying Hawk"),
			Timestamp:   1353832234,
			Nonce:       "j4h3g2",
			Ext:         "some-app-ext-data"}
		h, _ := hd.Create()
		h.Validate()
		if got, want := h.GetReqHash(), "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY="; got != want {
			t.Errorf("SetPayloadHash failed:\n  got:  %s\n  want: %s", got, want)
		}
		h.Finalize([]byte("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"))
		if got, want := h.GetReqMAC(), "aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw="; got != want {
			t.Errorf("SetMAC failed:\n  got:  %s\n  want: %s", got, want)
		}
		if got, want := h.GetAuthorization("dh37fgj492je"), `Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", hash="Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=", ext="some-app-ext-data", mac="aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw="`; got != want {
			t.Errorf("GetAuthorization failed:\n  got:  %s\n  want: %s", got, want)
		}
	})
}

func TestCreate(t *testing.T) {
	t.Run("Create-missing-Details-alg", func(t *testing.T) {
		hd := Details{
			Host:   "example.com",
			Port:   "8000",
			URI:    "/resource/1?b=1&a=2",
			Method: "POST",
		}
		_, err := hd.Create()
		if err != nil {
			t.Errorf("Create failed: no error on Details empty algorithm")
		}
	})
	t.Run("Create-missing-Details-host", func(t *testing.T) {
		hd := Details{
			Algorithm: crypto.SHA256,
			Port:      "8000",
			URI:       "/resource/1?b=1&a=2",
			Method:    "POST",
		}
		_, err := hd.Create()
		if err != nil {
			t.Errorf("Create failed: no error on Details empty host")
		}
	})
	t.Run("Create-missing-Details-port", func(t *testing.T) {
		hd := Details{
			Algorithm: crypto.SHA256,
			Host:      "example.com",
			URI:       "/resource/1?b=1&a=2",
			Method:    "POST",
		}
		_, err := hd.Create()
		if err != nil {
			t.Errorf("Create failed: no error on Details empty port")
		}
	})
	t.Run("Create-missing-Details-uri", func(t *testing.T) {
		hd := Details{
			Algorithm: crypto.SHA256,
			Host:      "example.com",
			Port:      "8000",
			Method:    "POST",
		}
		_, err := hd.Create()
		if err != nil {
			t.Errorf("Create failed: no error on Details empty uri")
		}
	})
	t.Run("Create-missing-Details-method", func(t *testing.T) {
		hd := Details{
			Algorithm: crypto.SHA256,
			Host:      "example.com",
			Port:      "8000",
			URI:       "/resource/1?b=1&a=2",
		}
		_, err := hd.Create()
		if err != nil {
			t.Errorf("Create failed: no error on Details empty method")
		}
	})
}

func TestEmpty(t *testing.T) {
	t.Run("Validate-missing", func(t *testing.T) {
		hd := Details{
			Algorithm: crypto.SHA256,
			Host:      "localhost",
			Port:      "8000",
			URI:       "/test",
			Method:    "GET"}
		h, _ := hd.Create()
		if h.Validate() {
			t.Errorf("Validate failed: returned true on missing content/contentType")
		}
	})
	t.Run("Finalize-empty-struct", func(t *testing.T) {
		h := Hawk{}
		if h.Finalize([]byte("secret")) {
			t.Errorf("Finalize failed: returned true on empty RequestDetails struct")
		}
	})
	t.Run("GetAuthorization-empty-struct", func(t *testing.T) {
		h := Hawk{}
		if h.GetAuthorization("nope") != "" {
			t.Errorf("GetAuthorization failed: returned non-empty string on empty RequestDetails struct")
		}
	})
}

func TestClient(t *testing.T) {
	t.Run("unknown-scheme", func(t *testing.T) {
		h := NewClient("jdoe", []byte("Syp9393"), crypto.SHA256, 6)
		_, err := h.NewRequest("GET", "ftp://localhost/hello", nil, "text/plain", "")
		if err == nil {
			t.Errorf("NewRequest failed: no error on unsupported scheme")
		}
	})
	t.Run("broken-url", func(t *testing.T) {
		h := NewClient("jdoe", []byte("Syp9393"), crypto.SHA256, 6)
		_, err := h.NewRequest("GET", "http://localhost:asd/hello", nil, "text/plain", "")
		if err == nil {
			t.Errorf("NewRequest failed: no error on broken URL")
		}
	})
	t.Run("http-port-8000", func(t *testing.T) {
		h := NewClient("jdoe", []byte("Syp9393"), crypto.SHA256, 6)
		req, err := h.NewRequest("POST", "http://localhost:8000/hello", nil, "text/plain", "")
		if err != nil {
			t.Errorf("NewRequest failed: %s", err.Error())
		}
		if got, want := req.Host, "localhost:8000"; got != want {
			t.Errorf("NewRequest failed:\n  got:  %s\n  want: %s", got, want)
		}
	})
	t.Run("https-port-8000", func(t *testing.T) {
		h := NewClient("jdoe", []byte("Syp9393"), crypto.SHA256, 6)
		req, err := h.NewRequest("POST", "https://localhost:8000/hello", nil, "text/plain", "")
		if err != nil {
			t.Errorf("NewRequest failed: %s", err.Error())
		}
		if got, want := req.Host, "localhost:8000"; got != want {
			t.Errorf("NewRequest failed:\n  got:  %s\n  want: %s", got, want)
		}
	})
	t.Run("https", func(t *testing.T) {
		h := NewClient("jdoe", []byte("Syp9393"), crypto.SHA256, 6)
		_, err := h.NewRequest("POST", "https://localhost/hello", nil, "text/plain", "")
		if err != nil {
			t.Errorf("NewRequest failed: %s", err.Error())
		}
	})
	t.Run("data", func(t *testing.T) {
		data := "Hello world!"
		body := io.Reader(strings.NewReader(data))
		h := NewClient("jdoe", []byte("Syp9393"), crypto.SHA256, 6)
		req, err := h.NewRequest("POST", "http://localhost/hello", body, "text/plain", "")
		if err != nil {
			t.Errorf("NewRequest failed: %s", err.Error())
		}
		if req.ContentLength == 0 {
			t.Errorf("NewRequest failed: content length 0")
		}
		if got, want := req.Header.Get("Content-Type"), "text/plain"; got != want {
			t.Errorf("NewRequest failed:\n  got:  %s\n  want: %s", got, want)
		}
		if req.Header.Get("Authorization") == "" {
			t.Errorf("NewRequest failed: header Authorization empty")
		}
	})
	t.Run("send-no-data", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			b, _ := ioutil.ReadAll(r.Body)
			if len(b) > 0 {
				t.Errorf("NewRequest failed: body not nil: %s", b)
			}
			fmt.Fprintln(w, "OK.")
		}))
		defer ts.Close()
		c := &http.Client{}
		hc := NewClient("jdoe", []byte("Syp9393"), crypto.SHA256, 6)
		req, err := hc.NewRequest("POST", ts.URL+"/hello", nil, "text/plain", "")
		_, err = c.Do(req)
		if err != nil {
			t.Errorf("NewRequest failed: %s", err.Error())
		}
	})
	t.Run("send-data", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			b, _ := ioutil.ReadAll(r.Body)
			if string(b) != "Hello world!" {
				t.Errorf("NewRequest failed: body not nil: %s", b)
			}
			fmt.Fprintln(w, "OK.")
		}))
		defer ts.Close()
		data := "Hello world!"
		body := strings.NewReader(data)
		c := &http.Client{}
		hc := NewClient("jdoe", []byte("Syp9393"), crypto.SHA256, 6)
		req, err := hc.NewRequest("POST", ts.URL+"/hello", body, "text/plain", "")
		_, err = c.Do(req)
		if err != nil {
			t.Errorf("NewRequest failed: %s", err.Error())
		}
	})
}
