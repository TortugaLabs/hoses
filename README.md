<img src="_static/hose_64x64.png" alt="">

# hoses

Enhanced SOCKSv5 proxy implementation
and related tools in Python3

Features:

- Implements SOCKS5 CONNECT and BIND commands.
- Adds SSL encryption with server and client certificate
  validation.
- TODO: Use threads and os.execvp on inetd?
- testing: https://reviews.freebsd.org/source/src/browse/main/tests/atf_python/
  - test only binary traffic
  - ssh tunnel
  - src -> dest
    - src->dest oneshot
      - IPv4, IPv6, DNS, UNIX
    - src->dest multiple
      - bg | persist
      - IPv4, IPv6, DNS, UNIX
  - src [socksified] -> proxy -> dest
    - IPv4, IPv6, DNS, UNIX
    - plain,SSL,SSL-clientauth
    - ??good cert, bad cert - accept rule, patt mach deny rule??
  - src -> proxy -> [socksified] dest
    - oneshot
      - IPv4, IPv6, DNS, UNIX
      - plain,SSL,SSL-clientauth
    - multiple
      - bg | presist
      - IPv4, IPv6, DNS, UNIX
- debugging


Commands:

- proxy - SOCKS5 protocol proxy
- connect - `netcat` but may use SOCKS5 proxy with optional SSL
- listen - `netcat -l` but may use SOCKS5 proxy with optional SSL

The following references were consulted:

- https://www.electricmonk.nl/log/2018/06/02/ssl-tls-client-certificate-verification-with-python-v3-4-sslcontext/
- https://github.com/MisterDaneel/pysoxy
- https://stackoverflow.com/questions/7186601/is-socks5-bind-persistent-or-one-time-only
- https://en.wikipedia.org/wiki/SOCKS

## Issues

- Deal with SSL nonblocking sockets
  - https://docs.python.org/3/library/ssl.html#notes-on-non-blocking-sockets





