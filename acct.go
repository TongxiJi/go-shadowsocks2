package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	ACCT_START  = "acct_start"
	ACCT_UPDATE = "acct_update"
	ACCT_STOP   = "acct_stop"
	ACCT_PROXY  = "acct_proxy"
)

type BaseModel struct {
	Data    json.RawMessage `json:"data"`
	Code    int             `json:"code"`
	Message string          `json:"message"`
}

type Token struct {
	TokenId string `json:"tokenId"`
}

func clientAcctStart(username, password string) (tokenId *string, err error) {
	authInfo, err := encodeToken(map[string]string{
		"acct":     ACCT_START,
		"username": username,
		"password": password,
		"time":     strconv.FormatInt(time.Now().Unix(), 10),
	})
	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s", config.Client), nil)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("Authorization", *authInfo)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		err = fmt.Errorf("http request err:%v", err)
		return nil, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf("http read response err:%v", err)
		return nil, err
	}
	jwtMapClaims, err := decodeToken(string(body))
	if err != nil {
		return nil, err
	}
	tokenStr := jwtMapClaims["tokenId"]
	return &tokenStr, nil
}

func clientAcctUpdate(username, tokenId string) (err error) {
	authInfo, err := encodeToken(map[string]string{
		"acct":     ACCT_UPDATE,
		"username": username,
		"tokenId": tokenId,
		"time":     strconv.FormatInt(time.Now().Unix(), 10),
	})
	if err != nil {
		return err
	}

	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s", config.Client), nil)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("Authorization", *authInfo)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		err = fmt.Errorf("http request err:%v", err)
		return err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf("http read response err:%v", err)
		return err
	}
	jwtMapClaims, err := decodeToken(string(body))
	if err != nil {
		return err
	}
	if  strings.EqualFold(jwtMapClaims["code"],"0") {
		return nil
	} else {
		return fmt.Errorf(jwtMapClaims["message"])
	}
}


func clientAcctStop(username, tokenId string) (err error) {
	authInfo, err := encodeToken(map[string]string{
		"acct":     ACCT_STOP,
		"username": username,
		"tokenId": tokenId,
		"time":     strconv.FormatInt(time.Now().Unix(), 10),
	})
	if err != nil {
		return err
	}

	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s", config.Client), nil)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("Authorization", *authInfo)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		err = fmt.Errorf("http request err:%v", err)
		return err
	}
	defer res.Body.Close()
	return nil
}

func serverAcctStart(username, password string) (resBody *string, tokenId *string, err error) {
	//TODO 接实际认证服务

	if strings.EqualFold(config.User[username], password) {
		tokenStr := strconv.FormatInt(time.Now().Unix(), 10)
		resBody, err = encodeToken(map[string]string{
			"tokenId": tokenStr,
		})
		return resBody, &tokenStr, err
	}
	return nil, nil, fmt.Errorf("serverAcctStart auth failed %s %s", username, password)
}


func serverAcctUpdate(username, tokenId string) (resBody *string,err error) {
	//TODO 接实际认证服务

	if user:= userManager.Get(tokenId);user != nil {
		resBody, err = encodeToken(map[string]string{
			"code": "0",
			"message":fmt.Sprintf("username:%s,tokenId:%s refresh succeed", username, tokenId),
		})
	} else {
		resBody, err = encodeToken(map[string]string{
			"code": "-1",
			"message":fmt.Sprintf("username:%s,tokenId:%s is not existed", username, tokenId),
		})
	}
	return resBody,err
}

func serverAcctStop(username, tokenId string) (err error) {
	//TODO 接实际认证服务

	userManager.Del(tokenId)
	return nil
}
