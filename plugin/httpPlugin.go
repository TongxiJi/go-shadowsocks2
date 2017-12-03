package plugin

import (
	"net/http"
	"net"
	"bufio"
	"log"
	"strings"
	"io/ioutil"
	"bytes"
)

type UserDetails struct {
	UserName string
	Password string
}

type HttpPlugin struct {
	AuthUser func(userDetail *UserDetails) (e error)
}

func (h *HttpPlugin) Handle(tcpConn *net.TCPConn) (error) {
	reader := bufio.NewReader(tcpConn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println(request.Header)
	if strings.EqualFold(request.RequestURI, "/user_manager") {
		bodyBuffer := bytes.NewBufferString("Hello World")
		bodyReader := ioutil.NopCloser(bodyBuffer)
		response := &http.Response{
			Status:        "401 Unauthozied",
			StatusCode:    http.StatusUnauthorized,
			Proto:         "HTTP/1.1",
			Header:        http.Header(make(map[string][]string)),
			Body:          bodyReader,
			ContentLength: int64(bodyBuffer.Len()),
			Close:         false,
		}
		response.Header.Add("WWW-authenticate", "Basic Realm=\"test\"")
		return response.Write(tcpConn)
	}

	return err
}