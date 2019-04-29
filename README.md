go-hawk
=======

[![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/gitlab.com/tdely/go-hawk) [![License MIT](https://img.shields.io/badge/License-MIT-red.svg?style=flat)](https://gitlab.com/tdely/go-hawk/blob/master/LICENSE) [![Build Status](https://gitlab.com/tdely/go-hawk/badges/master/build.svg)](https://gitlab.com/tdely/go-hawk/commits/master) [![Coverage Report](https://gitlab.com/tdely/go-hawk/badges/master/coverage.svg)](https://gitlab.com/tdely/go-hawk/commits/master) [![Coverage Report](https://goreportcard.com/badge/gitlab.com/tdely/go-hawk)](https://goreportcard.com/report/gitlab.com/tdely/go-hawk)

Package hawk provides a quick and easy way to send HTTP requests with
Hawk authentication.

Installation
------------

```
go get -u gitlab.com/triumvir/nxal
```


Getting Started
---------------

Easiest is to use the provided client:

```go
import (
    "crypto"
    hawk "gitlab.com/tdely/go-hawk"
    "net/http"
    "strings"
)

c := &http.Client{}
hc := hawk.NewClient("your-hawk-id", []byte("secret"), crypto.SHA256, 6)
body := strings.NewReader("Hello world!")
req, err := hc.NewRequest("POST", "https://example.com/greeting", body, "text/plain", "some-app-ext-data")
resp, err := c.Do(req)
// Check validity of response
valid := hc.ValidateResponse(*resp)
```

But if you want to not do payload verification or want to make life harder:

```go
import (
    "crypto"
    hawk "gitlab.com/tdely/go-hawk"
    "net/http"
    "strings"
    "time"
)

c := &http.Client{}
body := strings.NewReader("Hello world!")
req, _ := http.NewRequest("POST", "https://example.com/greeting", body)
hd := hawk.Details{
    Algorithm:   crypto.SHA256,
    Host:        "example.com",
    Port:        "443",
    URI:         "/greeting",
    ContentType: "plain/text",
    Content:     []byte("Hello world!"),
    Method:      "POST",
    Ext:         "some-app-ext-data"}
hd.Timestamp = time.Now().Unix()
hd.Nonce = hawk.NewNonce(6)
h, _ := hd.Create()
// h.Validate()
h.Finalize([]("secret"))
auth := h.GetAuthorization("your-hawk-id")
req.Header.Add("Content-Type", "plain/text")
req.Header.Add("Authorization", auth)
resp, err := c.Do(req)
// valid := h.ValidateResponse([]byte("justtesting"), *resp)
```
