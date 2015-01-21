a golang radius library
=============================
[![Build Status](https://travis-ci.org/bronze1man/radius.svg)](https://travis-ci.org/bronze1man/radius)
[![GoDoc](https://godoc.org/github.com/bronze1man/radius?status.svg)](https://godoc.org/github.com/bronze1man/radius)
[![docs examples](https://sourcegraph.com/api/repos/github.com/bronze1man/radius/badges/docs-examples.png)](https://sourcegraph.com/github.com/bronze1man/radius)
[![Total views](https://sourcegraph.com/api/repos/github.com/bronze1man/radius/counters/views.png)](https://sourcegraph.com/github.com/bronze1man/radius)

This project forks from https://github.com/jessta/radius

### document
http://godoc.org/github.com/bronze1man/radius
http://en.wikipedia.org/wiki/RADIUS


### example
```go
package main

import (
	"fmt"
	"github.com/bronze1man/radius"
)

type radiusService struct{}

func (p radiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
    // a pretty print of the request.
	fmt.Printf("[Authenticate] %s\n", request.String())
	npac := request.Reply()
	switch request.Code {
	case radius.AccessRequest:
	    // check username and password
		if request.GetUsername() == "a" && request.GetPassword() == "a" {
			npac.Code = radius.AccessAccept
			return npac
		} else {
			npac.Code = radius.AccessReject
			npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.ReplyMessage, Value: []byte("you dick!")})
			return npac
		}
	case radius.AccountingRequest:
	    // accounting start or end
		npac.Code = radius.AccountingResponse
		return npac
	default:
		npac.Code = radius.AccessAccept
		return npac
	}
}

func RunVpnAccount() {
	s := radius.NewServer(":1812", "sEcReT", radiusService{})
	fmt.Println("waiting for packets...")
	err := s.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
```


