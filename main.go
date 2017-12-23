package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	//"net/url"
	"os"
	"strings"
	"time"
	"encoding/json"
	"crypto/md5"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/TongxiJi/go-shadowsocks2/socks"
	"github.com/TongxiJi/go-shadowsocks2/plugin"
	"github.com/dgrijalva/jwt-go"
	"net"
	"os/exec"
	//"os/signal"
	//"syscall"
	"path/filepath"
	"os/signal"
	"syscall"
)

const HMAC_STATIC_KEY = "32131dsadsaj923j8f72320fnnvngg"
const DIAL_TIME_OUT = time.Second * 20

const (
	ACT_START = "act_start"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
	User       map[string]string `json:"user"`
}

func logf(f string, v ...interface{}) {
	if config.Verbose {
		log.Printf(f, v...)
	}
}

var username, password string
var userManager *OnlineUserManager
var httpPlugin *plugin.HttpPlugin

func main() {

	var flags struct {
		Client     string
		Server     string
		Cipher     string
		Key        string
		UserName   string
		Password   string
		Keygen     int
		Socks      string
		RedirTCP   string
		RedirTCP6  string
		TCPTun     string
		UDPTun     string
		UDPSocks   bool
		ConfigFile string
	}

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.ConfigFile, "config", "", "assign config file")
	flag.StringVar(&flags.Cipher, "cipher", "CHACHA20-IETF", "available ciphers: " + strings.Join(core.ListCipher(), " "))
	//flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
	flag.IntVar(&flags.Keygen, "keygen", 0, "generate a base64url-encoded random key of given length in byte")
	flag.StringVar(&flags.UserName, "username", "", "(client-only) username")
	flag.StringVar(&flags.Password, "password", "", "(client-only) password")
	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.StringVar(&flags.Client, "c", "", "client connect address or url")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	//flag.BoolVar(&flags.UDPSocks, "u", false, "(client-only) Enable UDP support for SOCKS")
	//flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	//flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
	flag.StringVar(&flags.TCPTun, "tcptun", "", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	//flag.StringVar(&flags.UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5 * time.Minute, "UDP tunnel timeout")
	flag.Parse()

	if flags.Keygen > 0 {
		key := make([]byte, flags.Keygen)
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
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}

	httpPlugin = &plugin.HttpPlugin{
		DecodeToken: decodeToken,
		EncodeToken: encodeToken,
		ServerHandelResponse: serverHandelResponse,
		ClientHandelResponse: clientHandelResponse,
	}

	if flags.Client != "" {
		// client mode
		addr := flags.Client
		cipher := flags.Cipher
		username = flags.UserName
		password = flags.Password
		var err error

		//if strings.HasPrefix(addr, "ss://") {
		//	addr, cipher, password, err = parseURL(addr)
		//	if err != nil {
		//		log.Fatal(err)
		//	}
		//}

		md5Slice := md5.Sum([]byte(password))
		ciph, err := core.PickCipher(cipher, key, string(md5Slice[:]))
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

		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTun(p[0], addr, p[1], ciph.StreamConn)
			}
		}

		if flags.Socks != "" {
			socks.UDPEnabled = flags.UDPSocks
			go socksLocal(flags.Socks, addr, ciph.StreamConn)
			//if flags.UDPSocks {
			//	go udpSocksLocal(flags.Socks, addr, ciph.PacketConn)
			//}
		}


		//go startOpenVPN()
	}

	if flags.Server != "" {
		// server mode
		addr := flags.Server
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

		if len(flags.ConfigFile) != 0 {
			cipher := flags.Cipher

			file, err := os.Open(flags.ConfigFile)
			if err != nil {
				logf("read config error: %v", err)
				return
			}
			defer file.Close()
			json.NewDecoder(file).Decode(&config)
			logf("config %v", config)

			for k, v := range config.User {
				md5Slice := md5.Sum([]byte(v))
				ciph, err := core.PickCipher(cipher, key, string(md5Slice[:]))
				if err != nil {
					logf("get cipher error:%v", err)
					continue
				}

				//test
				userManager.Add(k, &OnlineUser{
					Conns:make([]net.Conn, 0),
					Cipher:ciph,
				})
			}
		}

		ticker := time.NewTicker(time.Second * 10)
		go func() {
			for range ticker.C {
				length := 0
				userManager.Range(func(userToken, user interface{}) bool {
					length ++
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
	username := token["username"]
	if len(username) == 0 {
		err = fmt.Errorf("username is empty")
		return
	}
	if !strings.EqualFold(config.User[username], token["password"]) {
		logf("%s auth info is not correct", username)
		err = fmt.Errorf("auth info is not correct")
		return
	}

	resultClaims := jwt.MapClaims{
		"code":0,
		"message":"hello world",
	}
	result := jwt.NewWithClaims(jwt.SigningMethodHS256, resultClaims)
	resultSignedString, err := result.SignedString([]byte(HMAC_STATIC_KEY))
	return &resultSignedString, &username, err
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
