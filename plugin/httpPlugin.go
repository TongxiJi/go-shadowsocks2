package plugin

import (
	"net/http"
	"net"
	"bufio"
	"errors"
	"fmt"
)

type HttpPlugin struct {
	DecodeToken func(token string) (authInfo *string, err error)
	EncodeToken func(authInfo string) (token *string, err error)
	Auth        func(authInfo string) (tokenId *string, err error)
}

func (h *HttpPlugin) ClientHandle(server string, authInfo string, rc net.Conn) (err error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", server), nil)
	if token, err := h.EncodeToken(authInfo); err != nil {
		return err
	} else {
		req.Header.Add("Authorization", *token)
	}
	if err = req.Write(rc); err != nil {
		return err
	}
	reader := bufio.NewReader(rc)
	if _, err := http.ReadResponse(reader, req); err != nil {
		return err
	}
	return nil
}

func (h *HttpPlugin) ServerHandle(c net.Conn) (tokenId *string, err error) {
	reader := bufio.NewReader(c)
	if req, err := http.ReadRequest(reader); err != nil {
		return nil, err
	} else {
		var token string
		if token = req.Header.Get("Authorization"); len(token) == 0 {
			return nil, errors.New("cant get user info from http basic auth")
		} else {
			var authInfo *string
			if authInfo, err = h.DecodeToken(token); err != nil {
				return nil, err
			}
			if tokenId, err = h.Auth(*authInfo); err != nil {
				return nil, err
			}
		}
	}
	res := &http.Response{
		ContentLength: 0,
		Status:        "200 OK",
		StatusCode:    200,
		Close:         false,
	}
	if err = res.Write(c); err != nil {
		return nil, err
	}
	return tokenId, err
}