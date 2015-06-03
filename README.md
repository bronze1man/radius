a golang radius library
=============================
[![Build Status](https://travis-ci.org/bronze1man/radius.svg)](https://travis-ci.org/bronze1man/radius)
[![GoDoc](https://godoc.org/github.com/bronze1man/radius?status.svg)](https://godoc.org/github.com/bronze1man/radius)
[![docs examples](https://sourcegraph.com/api/repos/github.com/bronze1man/radius/badges/docs-examples.png)](https://sourcegraph.com/github.com/bronze1man/radius)
[![Total views](https://sourcegraph.com/api/repos/github.com/bronze1man/radius/counters/views.png)](https://sourcegraph.com/github.com/bronze1man/radius)
[![GitHub issues](https://img.shields.io/github/issues/bronze1man/radius.svg)](https://github.com/bronze1man/radius/issues)
[![GitHub stars](https://img.shields.io/github/stars/bronze1man/radius.svg)](https://github.com/bronze1man/radius/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/bronze1man/radius.svg)](https://github.com/bronze1man/radius/network)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/bronze1man/radius/blob/master/LICENSE)

This project forks from https://github.com/jessta/radius

### document
* http://godoc.org/github.com/bronze1man/radius
* http://en.wikipedia.org/wiki/RADIUS

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

func main() {
	s := radius.NewServer(":1812", "sEcReT", radiusService{})
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	errChan := make(chan error)
	go func() {
		fmt.Println("waiting for packets...")
		err := s.ListenAndServe()
		if err != nil {
			errChan <- err
		}
	}()
	select {
	case <-signalChan:
		log.Println("stopping server...")
		s.Stop()
	case err := <-errChan:
		log.Println("[ERR] %v", err.Error())
	}
}
```

### implemented
* a radius server can handle AccessRequest request from strongswan with ikev1-xauth-psk
* a radius server can handle AccountingRequest request from strongswan with ikev1-xauth-psk

### notice
* A radius client has not been implement.
* It works , but it is not stable.

### reference
* EAP MS-CHAPv2 packet format 								http://tools.ietf.org/id/draft-kamath-pppext-eap-mschapv2-01.txt
* EAP MS-CHAPv2 											https://tools.ietf.org/html/rfc2759
* RADIUS Access-Request part      							https://tools.ietf.org/html/rfc2865
* RADIUS Accounting-Request part  							https://tools.ietf.org/html/rfc2866
* RADIUS Support For Extensible Authentication Protocol 	https://tools.ietf.org/html/rfc3579
* RADIUS Implementation Issues and Suggested Fixes 			https://tools.ietf.org/html/rfc5080

### TODO
* avpEapMessaget.Value error handle.
* implement eap-MSCHAPV2 server side.
* implement radius client side.