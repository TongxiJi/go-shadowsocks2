package main

const OpenvpnConfigTemplate  =
`
client
dev tun
proto tcp
sndbuf 0
rcvbuf 0
resolv-retry infinite
nobind
persist-key
persist-tun
auth SHA512
cipher none
comp-lzo
max-routes 20000
verb 3

connect-retry-max 3

<ca>
-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIJAJOUvF+bD3D5MA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCENoYW5nZU1lMB4XDTE3MTAyMDA3NDA1MloXDTI3MTAxODA3NDA1MlowEzER
MA8GA1UEAwwIQ2hhbmdlTWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQC/AuxyouDvPvteHeHBHtYl2GkbgM9xFlA8BAu0O7ObMrG63CZAd/yb/b5KYZG+
QTX133lYL/yH3FaeXofatIkwIG6bEoJbKMqHaC3KjRjEhCGknHM309uhdupnO6dy
o6W1y9CZ4tYNuzd087L/O5I9bv5Z1S2KAdUkX21j5BSw5CnD1lsMfQznkBrF+KOG
tv7fzOHatAe2rOYzS3EgvHWfC12hz9PphUNzh+gAb/fTqUeWwDQ2ajBSFOcZX7II
eHxJUYEF08p/ShSzh2jO8yIqUZjG1l9AReXiV1htkI0h6ymjaiwl2OdSBV1WRO0Y
XeKoaP4MYyVA3M4EEJlRG8jFAgMBAAGjgYEwfzAdBgNVHQ4EFgQUvZ2GzQ21O1Eu
6lLDqVJBLgVg1IQwQwYDVR0jBDwwOoAUvZ2GzQ21O1Eu6lLDqVJBLgVg1IShF6QV
MBMxETAPBgNVBAMMCENoYW5nZU1lggkAk5S8X5sPcPkwDAYDVR0TBAUwAwEB/zAL
BgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBALE8P4Tbkr28TSKVf9DISGLq
EFrgi/ISrD9niKqMug0D7/yHaP/id9LW+aVt3az5/rJY0t+T8EC125bNoX4aqexO
3BQYjbYQg2kwjWNepgmaeE1T8RXqzAjmrBPIni3X/3bJWWBkhcJHd6Na8E6AB9WD
i4gC4yp2ERRv5kGclCuMz1IHckIKIhDkqCgOMU1DM0NnefpL73iFH/ytpJEhUIwm
CGyeErC7xbVlSue4wnCF49TWoWcWCOJ3XiSYC961j3W/90kgxKWxFJdxAIyT97ol
KHmUgddvnqKzC5z0bT0/QmlUN7GOwgs0Zk8ftBKqPHVjOp5aAVpyYX8k6V0tEVQ=
-----END CERTIFICATE-----
</ca>
`

//ovpn_config += string.Format("remote {0} {1}", remoteIp, remotePort) + Environment.NewLine;
//ovpn_config += string.Format("auth-user-pass \"{0}\"", PSD_PATH.Replace(@"\", @"\\")) + Environment.NewLine;
//ovpn_config += string.Format("socks-proxy {0} {1} \"{2}\"", socksIp, socksPort, PSD_PATH.Replace(@"\", @"\\")) + Environment.NewLine;
//
//public static string FMT_ROUTE_ADD = "route {0} {1} vpn_gateway " + Environment.NewLine;