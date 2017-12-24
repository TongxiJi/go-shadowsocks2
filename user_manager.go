package main

import (
	"net"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"crypto/md5"
)

const ACCT_UPDATE_INTERVAL  = time.Minute * 3
const ACCT_UPDATE_TIME_OUT =  time.Minute * 10
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

func (um *OnlineUserManager) Add(userToken string) {
	md5Slice := md5.Sum([]byte(userToken))
	ciph, err := core.PickCipher(config.Cipher, []byte(config.Key), string(md5Slice[:]))
	if err != nil {
		logf("generate cipher error:%v", err)
		return
	}
	newUser := NewOnlineUser(ciph)
	newUser.Timer=time.AfterFunc(ACCT_UPDATE_TIME_OUT, func() {
		um.Del(userToken)
	})

	um.discAllConns(userToken)
	um.Store(userToken, newUser)
}

func (um *OnlineUserManager) Refresh(userToken string) {
	if v, ok := um.Load(userToken); ok {
		  v.(*OnlineUser).Timer.Reset(ACCT_UPDATE_TIME_OUT)
	}
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
