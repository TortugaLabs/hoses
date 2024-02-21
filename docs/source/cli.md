# Command Line Interface

```{argparse}
   :filename: ../hoses/__main__.py
   :func: cli_parse
```

## Examples

### Proxy

The main usage is as a socks proxy.

Basic socks5 compatible proxy:

```bash
hoses -S * -P 1080 proxy
```
- `-S *` will listen on all IPv4 and IPv6 addresses.
- `-P 1080` listen on port 1080

Enable TLS and listen only on loopback address:

```bash
hoses -S 127.0.0.1 -P 3340 --cert server.crt --key server.key
```
Enable TLS and enable client certificate verification:
- `--cert server.crt` : file path to server certificate
- `--key server.key` : file path to corresponding key.

```bash
hoses -S 127.0.0.1 -P 3340 --cert server.crt --key server.key --ca ca.crt
```
- `--ca ca.crt` Certificate file signing client certificates (or the client
  certificate itself for self-signed certificates.

### netcat server

It can be used as `netcat --listen` replacement.

Listen on localhost, port 4040 and run a command:

```bash
hose listen --exec localhost 4040 'sh -c "python3 eliza.py"
```

Listen on unix socket on the socks server, and forward
connections to port 22 on remotehost.  And persist bindings.

```bash
hose -S socks-server -P 1080 listen -p unix:/tmp/sshsock 0 remotehost 22
```

Like previous but with TLS:

```bash
hose -S socks-server -P 1080 --cert client.crt --key client.key --ca ca.crt listen -p unix:/tmp/sshsock 0 remotehost 22
```

### netcat client

It can be used as a netcat client to connect to network ports.

Connect to remote:
```bash
hose connect remotehost 4583
```

Connect to a remote TLS server with certificate based client authentication
```bash
hose --cert client.crt --key client.key --ca ca.crt connect remotehost 4583
```

Connect to a remote host through a SSL socks proxy with client authentication
```bash
hose -S socks-server -P 1080 --cert client.crt --key client.key --ca ca.crt connect remotehost 4583
```

### stunnel

This is used as a replacement for `stunnel`.

Accept TLS connections and forward them to a different port.  This is used
to provide TLS encryption to protocol servers that do not support this
out of the box.

```bash
hose --cert server.crt --key server.key listen --unwrap -p localhost 8011 remotehost 11
```

Accept unencrypted connection and forward them to a TLS server.  This is used to
give TLS encryption to protocol clients that do not support it out of the box.
```bash
hose --cert server.crt --key server.key listen --wrap -p localhost 11 remotehost 8011
```

### SSH tunnel
You can use it as an ssh proxy command to make ssh go through a Socks
proxy:

```bash
ssh -o "ProxyCommand hoses -S sockserver -P 1080 connect %h %p" remotehost
```

## Environment variables

- `HOSES_PROXY` : Used to configure the `-S` `--sockss-server` and
  `-P` `--sockss-port` options.  It takes a value of _hostname_ : _port_ .
- `HOSES_ACCESS_RULES` : Command line `-a` `--access` options.
  Access rules specification.
- `HOSES_TlS_CERT` : Command line `--cert`, TLS certificate.  Used for
  servers and clients to identify each other.  For clients, it is optional,
  whereas for servers, it is mandatory.
- `HOSES_TLS_KEY` : Command line `--key`.  Key for the corresponding\
  certificate `--cert`.
- `HOSES_TLS_CA` : Certificate used to validate peers.  For clients, it
  would be either the CA that is signing the server's certificate.
  Similarly, for servers, it would be the CA that is signing the client's
  certificates.  Self-signed certificates are allowed here, but then it
  limits the signed certificates to one, so it is pretty useless for
  identifying client.
- `HOSES_LOGCFG` : Command line for `--log-cfg`.  Logging config file.
  See logging below.

## Logging

This software makes use of the standard [python logging][pylog]
library.  It can be configured via two options:

- `--log-cfg` _FILE_ : Configure logging from file.  See
  [Configuring Logging][logcfg] on the file cormat.
- `--log-opt` _KEY=VALUE_ : Pass configuration keys to [basicConfig].

Example:

```bash
--log-opt level=DEBUG --log-opt filename=logfile.txt
```
See [Log Levels][levels] for possible log level options.

  [pylog]: https://docs.python.org/3/howto/logging.html
  [logcfg]: https://docs.python.org/3/howto/logging.html#configuring-logging
  [basicConfig]: https://docs.python.org/3/library/logging.html#logging.basicConfig
  [levels]: https://docs.python.org/3/library/logging.html#logging-levels
