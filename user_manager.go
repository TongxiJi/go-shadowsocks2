package main

import (
	"net"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
)

const ACCT_TIME_OUT = time.Minute * 1
const ACCT_UPDATE_MAX_FAILD_TIMES = 3

type OnlineUser struct {
	Timer  *time.Timer
	Conns  []net.Conn
	Cipher core.Cipher
}

func NewOnlineUser(ciph core.Cipher) *OnlineUser{
	return &OnlineUser{
		Conns:  make([]net.Conn, 0),
		Cipher: ciph,
	}
}

type OnlineUserManager struct {
	sync.Map
}

func (um *OnlineUserManager) Add(userToken string, user *OnlineUser) {
	um.discAllConns(userToken)
	um.Store(userToken, user)
}

func (um *OnlineUserManager) Get(userToken string) *OnlineUser {
	if v, ok := um.Load(userToken); ok {
		return v.(*OnlineUser)
	}
	return nil
}

func (um *OnlineUserManager) Del(userToken string) {
	um.discAllConns(userToken)
	um.Delete(userToken)
}

func (um *OnlineUserManager) discAllConns(userToken string) {
	if v, ok := um.Load(userToken); ok {
		for _, conn := range v.(*OnlineUser).Conns {
			if conn != nil {
				conn.Close()
			}
		}
	}
}

func (um *OnlineUserManager) addConn(userToken string, conn net.Conn) {
	if v, ok := um.Load(userToken); ok {
		v.(*OnlineUser).Conns = append(v.(*OnlineUser).Conns, conn)
	}
}

func (um *OnlineUserManager) delConn(userToken string, conn net.Conn) {
	if v, ok := um.Load(userToken); ok {
		conns := v.(*OnlineUser).Conns
		for i, c := range conns {
			if c == nil {
				v.(*OnlineUser).Conns = append(conns[:i], conns[i+1:]...)
			} else if conn == c {
				v.(*OnlineUser).Conns = append(conns[:i], conns[i+1:]...)
			}
		}
	}
}

//func (um *OnlineUserManager)ApiAcctStart(user *string, psd *string, otherInfo *string) (sessionId *string) {
//	return nil
//}
//
//func (um *OnlineUserManager)ApiAcctUpdate(user *string, sessionId *string, otherInfo *string) (success bool, err error) {
//
//	return
//}
//
//func (um *OnlineUserManager)ApiAcctStop(user *string, sessionId *string, otherInfo *string) {
//}
