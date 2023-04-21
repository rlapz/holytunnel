# holytunnel
Bypass DPI censorship, inspired by GreenTunnel.


## Note
For a better experience, please use `dnscrypt-proxy` too or another similar program since this program doesn't support (and probably never) Dot/Doh DNS query.


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
