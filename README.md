<img src="_static/hose_64x64.png" alt="">

# hoses

Enhanced SOCKSv5 proxy implementation
and related tools in Python3

Features:

- Implements SOCKS5 CONNECT and BIND commands.
- Adds SSL encryption with server and client certificate
  validation.
- Includes a fairly untested/extensible access module.

Commands:

- proxy - SOCKS5 protocol proxy
- connect - `netcat` but may use SOCKS5 proxy with optional SSL
- listen - `netcat -l` but may use SOCKS5 proxy with optional SSL

## Issues

- bind status message doesn't report the client's IP address.
- Deal with SSL nonblocking sockets
  - https://docs.python.org/3/library/ssl.html#notes-on-non-blocking-sockets

## TODO

- test Access module
- test audit log
- inetd-server : setenv for peercert, peersock
- use threads for port persist port forwarders?
- for inetd mode, use fork and os.execvp?
- testing: https://reviews.freebsd.org/source/src/browse/main/tests/atf_python/

## References

- [pysoxy: Python socks proxy](https://github.com/MisterDaneel/pysoxy)
- [Wikipedia artilce on SOCKS protocol](https://en.wikipedia.org/wiki/SOCKS)
- [TLS client certificate verification with Python](https://www.electricmonk.nl/log/2018/06/02/ssl-tls-client-certificate-verification-with-python-v3-4-sslcontext/)

## Changes

- 1.0.0 : Initial release

***
Hose Icon made by [Smashicons](https://www.flaticon.com/authors/smashicons)
from [www.flaticon.com](https://www.flaticon.com).
