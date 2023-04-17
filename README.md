# holy_tunnel
Anti censorship DNS DPI, inspired by GreenTunnel.


## Note
Please use `dnscrypt-proxy` for better experience, since this program doesn't support (And probably never) Dot/Doh DNS query.


## How to build
```
go build
```


## How to run
```
./holytunnel [LISTEN_ADDR]:[LISTEN_PORT]
```

Example

```
./holytunnel 127.0.0.1:8001
```
