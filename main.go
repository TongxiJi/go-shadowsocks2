package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	//"net/url"
	"crypto/md5"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/TongxiJi/go-shadowsocks2/plugin"
	"github.com/TongxiJi/go-shadowsocks2/socks"
	"github.com/dgrijalva/jwt-go"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"os/signal"
	"syscall"
)

const HMAC_STATIC_KEY = "32131dsadsaj923j8f72320fnnvngg"
const DIAL_TIME_OUT = time.Second * 20

const (
	ACCT_START  = "acct_start"
	ACCT_UPDATE = "acct_update"
	ACCT_STOP   = "acct_stop"
	ACCT_PROXY  = "acct_proxy"
)

var config struct {
	Client     string
	Server     string
	Cipher     string
	Key        string
	UserName   string
	Password   string
	TokenId    string
	Keygen     int
	Socks      string
	RedirTCP   string
	RedirTCP6  string
	TCPTun     string
	UDPTun     string
	UDPSocks   bool
	ConfigFile string
	UDPTimeout time.Duration
	User       map[string]string `json:"user"`
	Verbose    bool
}

func logf(f string, v ...interface{}) {
	if config.Verbose {
		log.Printf(f, v...)
	}
}

var userManager *OnlineUserManager
var httpPlugin *plugin.HttpPlugin

func main() {

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&config.ConfigFile, "config", "", "assign config file")
	flag.StringVar(&config.Cipher, "cipher", "CHACHA20-IETF", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	//flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
	flag.IntVar(&config.Keygen, "keygen", 0, "generate a base64url-encoded random key of given length in byte")
	flag.StringVar(&config.UserName, "username", "", "(client-only) username")
	flag.StringVar(&config.Password, "password", "", "(client-only) password")
	flag.StringVar(&config.Server, "s", "", "server listen address or url")
	flag.StringVar(&config.Client, "c", "", "client connect address or url")
	flag.StringVar(&config.Socks, "socks", "", "(client-only) SOCKS listen address")
	//flag.BoolVar(&flags.UDPSocks, "u", false, "(client-only) Enable UDP support for SOCKS")
	//flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	//flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
	flag.StringVar(&config.TCPTun, "tcptun", "", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	//flag.StringVar(&flags.UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse()

	if config.Keygen > 0 {
		key := make([]byte, config.Keygen)
		io.ReadFull(rand.Reader, key)
		fmt.Println(base64.URLEncoding.EncodeToString(key))
		return
	}

	//TODO 未指定客户端还是服务端运行时，需要接下去询问
	//if flags.Client == "" && flags.Server == "" {
	//	flag.Usage()
	//	return
	//}

	var key []byte
	if config.Key != "" {
		k, err := base64.URLEncoding.DecodeString(config.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}

	httpPlugin = &plugin.HttpPlugin{
		DecodeToken:          decodeToken,
		EncodeToken:          encodeToken,
		ServerHandelResponse: serverHandelResponse,
		ClientHandelResponse: clientHandelResponse,
	}

	if config.Client != "" {
		// client mode
		var err error

		//if strings.HasPrefix(addr, "ss://") {
		//	addr, cipher, password, err = parseURL(addr)
		//	if err != nil {
		//		log.Fatal(err)
		//	}
		//}
		var tokenId *string
		if tokenId, err = clientAcctStart(config.UserName, config.Password); err != nil {
			logf("clientAcctStart error:%v", err)
			return
		} else {
			config.TokenId = *tokenId
		}

		md5Slice := md5.Sum([]byte(config.TokenId))
		ciph, err := core.PickCipher(config.Cipher, key, string(md5Slice[:]))
		if err != nil {
			logf("set cipher error:%v", err)
			return
		}

		//ciph, err := core.PickCipher(cipher, key, password)
		//if err != nil {
		//	log.Fatal(err)
		//}

		//if flags.UDPTun != "" {
		//	for _, tun := range strings.Split(flags.UDPTun, ",") {
		//		p := strings.Split(tun, "=")
		//		go udpLocal(p[0], addr, p[1], ciph.PacketConn)
		//	}
		//}

		if config.TCPTun != "" {
			for _, tun := range strings.Split(config.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTun(p[0], config.Client, p[1], ciph.StreamConn)
			}
		}

		if config.Socks != "" {
			socks.UDPEnabled = config.UDPSocks
			go socksLocal(config.Socks, config.Client, ciph.StreamConn)
			//if flags.UDPSocks {
			//	go udpSocksLocal(flags.Socks, addr, ciph.PacketConn)
			//}
		}

		//go startOpenVPN()
	}

	if config.Server != "" {
		// server mode
		addr := config.Server
		//cipher := flags.Cipher
		//password := flags.Password

		//var err error

		//if strings.HasPrefix(addr, "ss://") {
		//	addr, cipher, password, err = parseURL(addr)
		//	if err != nil {
		//		log.Fatal(err)
		//	}
		//}

		//ciph, err := core.PickCipher(cipher, key, password)
		//if err != nil {
		//	log.Fatal(err)
		//}

		userManager = &OnlineUserManager{}

		if len(config.ConfigFile) != 0 {
			file, err := os.Open(config.ConfigFile)
			if err != nil {
				logf("read config error: %v", err)
				return
			}
			defer file.Close()
			json.NewDecoder(file).Decode(&config)
			logf("config %v", config)

			//for k, v := range config.User {
			//	md5Slice := md5.Sum([]byte(v))
			//	ciph, err := core.PickCipher(cipher, key, string(md5Slice[:]))
			//	if err != nil {
			//		logf("get cipher error:%v", err)
			//		continue
			//	}
			//
			//	//test
			//	userManager.Add(k, &OnlineUser{
			//		Conns:make([]net.Conn, 0),
			//		Cipher:ciph,
			//	})
			//}
		}

		ticker := time.NewTicker(time.Second * 10)
		go func() {
			for range ticker.C {
				length := 0
				userManager.Range(func(userToken, user interface{}) bool {
					length++
					logf("user token:%s,total conns:%d", userToken.(string), len(user.(*OnlineUser).Conns))
					return true
				})
				logf("total  online  user:%d", length)
			}
		}()

		//timer := time.NewTimer(time.Minute * 2)
		//go func() {
		//	<-timer.C
		//	userToken := "test"
		//	userManager.Del(userToken)
		//	logf("delete user %s and kick all connections", userToken)
		//}()

		//go udpRemote(addr)
		go tcpRemote(addr)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func decodeToken(tokenString string) (authInfo map[string]string, err error) {
	logf("decodeToken tokenString:%s", tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		//	return nil, fmt.Errorf("unexpected signing method:%v", token.Header["alg"])
		//}
		return []byte(HMAC_STATIC_KEY), nil
	})

	if err != nil {
		return nil, err
	}

	authInfo = make(map[string]string, 0)
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		for k, v := range claims {
			authInfo[k] = v.(string)
		}
		logf("decodeToken authInfo:%v", authInfo)
		return authInfo, nil
	}
	return nil, fmt.Errorf("decodeToken failed, %s", tokenString)
}

func encodeToken(authInfo map[string]string) (*string, error) {
	mapClaims := jwt.MapClaims{}
	for k, v := range authInfo {
		mapClaims[k] = v
	}
	logf("encode token mapClaims:%v", mapClaims)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	tokenString, err := token.SignedString([]byte(HMAC_STATIC_KEY))
	logf("encode token:%s", tokenString)
	return &tokenString, err
}

func serverHandelResponse(token map[string]string) (resBody, tokenId *string, err error) {
	logf("serverHandelResponse :%v", token)

	switch token["acct"] {
	case ACCT_START:
		if resBody, tokenId, err = serverAcctStart(token["username"], token["password"]); err != nil {
			logf("serverHandelResponse err:%v", err)
			return nil, nil, err
		}
		md5Slice := md5.Sum([]byte(*tokenId))
		ciph, err := core.PickCipher(config.Cipher, []byte(config.Key), string(md5Slice[:]))
		if err != nil {
			logf("generate cipher error:%v", err)
			return nil, nil, err
		}
		newUser := NewOnlineUser(ciph)
		newUser.Timer=time.AfterFunc(ACCT_TIME_OUT, func() {
			userManager.Del(*tokenId)
		})
		userManager.Add(*tokenId,newUser)

		return resBody, tokenId, nil
	case ACCT_UPDATE:
		break
	case ACCT_STOP:
		break
	case ACCT_PROXY:
		//username := token["username"]
		if tokenId,ok := token["tokenId"];ok {
			return nil, &tokenId, nil
		}
	}
	return nil, nil, fmt.Errorf("acct type \"%s\" not support", token["acct"])
}

func clientHandelResponse(authResponse string) (err error) {
	logf("clientHandelResponse :%s", authResponse)

	response, err := jwt.Parse(authResponse, func(token *jwt.Token) (interface{}, error) {
		//if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		//	return nil, fmt.Errorf("unexpected signing method:%v", token.Header["alg"])
		//}
		return []byte(HMAC_STATIC_KEY), nil
	})
	if err != nil {
		return err
	}

	if responseClaims, ok := response.Claims.(jwt.MapClaims); ok && response.Valid {
		logf("responseClaims:%v", responseClaims)
		return nil
	} else {
		return fmt.Errorf("claims is not valid:%v", responseClaims)
	}
}

//func parseURL(s string) (addr, cipher, password string, err error) {
//	u, err := url.Parse(s)
//	if err != nil {
//		return
//	}
//
//	addr = u.Host
//	if u.User != nil {
//		cipher = u.User.Username()
//		password, _ = u.User.Password()
//	}
//	return
//}
