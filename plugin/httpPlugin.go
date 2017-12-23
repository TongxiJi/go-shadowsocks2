package plugin

import (
	"net/http"
	"net"
	"bufio"
	"fmt"
	"io/ioutil"
	"bytes"
)

type HttpPlugin struct {
	EncodeToken          func(authInfo map[string]string) (token *string, err error)
	DecodeToken          func(token string) (authInfo map[string]string, err error)

	ServerHandelResponse func(authInfo map[string]string) (resBody *string, tokenId *string, err error)
	ClientHandelResponse func(resBody string) error
}

func (h *HttpPlugin) ClientHandle(server string, authInfo map[string]string, rc net.Conn) (err error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", server), nil)
	if token, err := h.EncodeToken(authInfo); err != nil {
		return err
	} else {
		req.Header.Set("Authorization", *token)
	}
	if err = req.Write(rc); err != nil {
		return err
	}
	reader := bufio.NewReader(rc)
	if res, err := http.ReadResponse(reader, req); err != nil {
		return err
	} else {
		if res.StatusCode != 200 {
			return fmt.Errorf(res.Status)
		}

		if res.StatusCode == 200 && res.ContentLength != 0 {

			if response, err := ioutil.ReadAll(res.Body); err != nil {
				return err
			} else {
				if err = h.ClientHandelResponse(string(response)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (h *HttpPlugin) ServerHandle(c net.Conn) (tokenId *string, err error) {
	reader := bufio.NewReader(c)
	var req *http.Request
	var resBody  *string
	if req, err = http.ReadRequest(reader); err == nil {
		var token string
		if token = req.Header.Get("Authorization"); len(token) == 0 {
			err = fmt.Errorf("cant get user info from http basic auth")
		} else {
			var authInfo map[string]string
			if authInfo, err = h.DecodeToken(token); err == nil {
				resBody, tokenId, err = h.ServerHandelResponse(authInfo)
			}
		}
	}

	res := &http.Response{
		ContentLength: 0,
		Close:         false,
	}

	if err == nil {
		res.StatusCode = 200
		res.Status = "200 OK!"
		if resBody != nil {
			res.ContentLength = int64(len(*resBody))
			res.Body = ioutil.NopCloser(bytes.NewBufferString(*resBody))
		}
	} else {
		res.StatusCode = 403
		res.Status = "403 forbidden!"
	}
	res.Write(c)
	return tokenId, err
}