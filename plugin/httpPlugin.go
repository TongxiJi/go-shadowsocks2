package plugin

import (
	"net/http"
	"net"
	"bufio"
	"errors"
	"fmt"
)

type UserDetails struct {
	UserName string
	Password string
}

type HttpPlugin struct {
	AuthUser func(userDetail *UserDetails) (e error)
}

func (h *HttpPlugin) ServerHandle(c net.Conn) (userDetail *UserDetails, err error) {
	reader := bufio.NewReader(c)
	if req, err := http.ReadRequest(reader); err != nil {
		return nil, err
	} else {
		if user, passord, ok := req.BasicAuth(); !ok {
			return nil,errors.New("cant get user info from http basic auth")
		} else {
			userDetail = &UserDetails{UserName: user, Password: passord}
			if err = h.AuthUser(userDetail); err != nil {
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
	return userDetail,err
}


func (h *HttpPlugin) ClientHandle(server string,user *UserDetails, rc net.Conn) (err error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", server), nil)
	req.SetBasicAuth(user.UserName, user.Password)
	if err = req.Write(rc); err != nil {
		return err
	}
	reader := bufio.NewReader(rc)
	if _, err := http.ReadResponse(reader, req); err != nil {
		return err
	}
	return nil
}
