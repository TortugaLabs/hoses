#!python
try:
  from icecream import ic
  ic.configureOutput(includeContext=True)
except ImportError:  # Graceful fallback if IceCream isn't installed.
  ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

import logging
import os
import select
import signal
import socket
import sys

import iopump
import pyus
import socks5x as s5x
import sslctx
import target
from pyus import src


def sslwrapper_factory(cert=None,key=None,ca=None,tls='none'):
  '''Create a closure to provide a SSL context to an outgoing connection

  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate
  :param str tls|None: Enable TLS
  '''

  if tls != 'wrap': return None

  def sslwrapper_inner(sock, host):
    context = sslctx.client_context(cert, key, ca)
    sock = context.wrap_socket(sock, server_side=False, server_hostname = sslctx.fixunixname(host))
    logging.debug("SSL established. Peer: {}".format(sock.getpeercert()))
    return sock

  return sslwrapper_inner


def inetd(address, port, dest, background, persist, cmd,cert=None,key=None,ca=None,tls='none'):
  ''' Wait for a incoming connection and exec process or tunnel to target

  :param str address: address to listen on
  :param int port: port to listen on
  :param bool persist: normally it will accept one connection and exit, if persist is true, it will accept multiple connections.
  :param list dest: destination target
  :param bool background: process should go to the background upon connect
  :param bool cmd: destination target is a command
  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate
  :param str tls|None: Enable TLS

  '''
  listener = s5x.bind_port(address,port)
  signal.signal(signal.SIGCHLD, pyus.reap_child_proc)

  if len(dest) == 0:
    if background:
      logging.error('Background option not compatible with empty destination (ignored)')
    if persist:
      logging.error('Persist option not compatible with empty destination (ignored)')

    while True:
      readers, _, _ = select.select([sys.stdin, listener], [], [], None)
      if sys.stdin in readers:
        # If we receive anything at this point, it is an error
        # so we quit
        return
      if listener in readers:
        sock,peer = listener.accept()
        break
  else:
    if persist:
      if background:
        pyus.daemonize()
      background = True
      while True:
        sock,peer = listener.accept()
        newpid = os.fork()
        if newpid == 0:
          break
        else:
          sock.close()
    else:
      sock,peer = listener.accept()

  if tls == 'unwrap':
    # Incoming SSL are port forwarded un-encrypted
    context = sslctx.server_context(cert, key, ca)
    sock = context.wrap_socket(sock, server_side=True)
    logging.debug("SSL established. Peer: {}".format(sock.getpeercert()))

  logging.info(f'Connected {peer} {src()}')
  listener.close()
  target.serve_target(sock, dest=dest, background = background, cmd = cmd, wrapper = sslwrapper_factory(cert, key, ca, tls))

def listener(sockss_server, sockss_port, address, port, dest, background, persist, cmd, cert, key, ca):
  ''' Wait for a incoming connection over a SOCKS proxy and exec process or tunnel to target

  :param str sockss_server: SOCKS proxy server address
  :param int sockss_port: SOCKS proxy server port
  :param str address: address to listen on
  :param int port: port to listen on
  :param bool persist: normally it will accept one connection and exit, if persist is true, it will accept multiple connections.
  :param list dest: destination target
  :param bool background: process should go to the background upon connect
  :param bool cmd: destination target is a command
  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate

  '''
  signal.signal(signal.SIGCHLD, pyus.reap_child_proc)
  if persist:
    if background:
      pyus.daemonize()
    background = True

  context = sslctx.client_context(cert, key, ca)

  while True:
    io = s5x.connect_to(sockss_server,sockss_port)
    if not context is None:
      io = context.wrap_socket(io, server_side=False, server_hostname = sslctx.fixunixname(sockss_server))
      logging.debug("SSL established. Peer: {}".format(io.getpeercert()))
    if not s5x.client_handshake(io):
      logging.error('Protocol error during handshake')
      sys.exit(1)

    s5x.sendmsg(io, s5x.S5CMD.BIND, s5x.SocksAddress(address), port)
    io.settimeout(None)
    status, addr, port = s5x.recvmsg(io)
    if status != s5x.S5STATUS.OK:
      logging.error('Sockss5 proxy error: {status}'.format(status = s5x.s5status_str(status)))
      sys.exit(3)
    if not persist: break

    newpid = os.fork()
    if newpid == 0:
      break
    else:
      io.close()

  target.serve_target(io, dest=dest, background=background, cmd=cmd)

def connect(sockss_server, sockss_port, target, port, cert, key, ca):
  """ Main connect function

  :param str sockss_server: SOCKS proxy server address
  :param int sockss_port: SOCKS proxy server port
  :param str target: address to connect
  :param int port: port to connect
  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate

  Connects to target:port using a SOCKS proxy.

  """
  context = sslctx.client_context(cert, key, ca)
  io = s5x.connect_to(sockss_server,sockss_port)
  if not context is None:
    io = context.wrap_socket(io, server_side=False, server_hostname = sslctx.fixunixname(sockss_server))
    logging.debug("SSL established. Peer: {}".format(io.getpeercert()))

  if not s5x.client_handshake(io):
    logging.error('Protocol error during handshake');
    sys.exit(1)

  s5x.sendmsg(io, s5x.S5CMD.CONNECT, s5x.SocksAddress(target), port)
  status, addr, port = s5x.recvmsg(io)
  if status != s5x.S5STATUS.OK:
    logging.error('Sockss5 proxy error: {status}'.format(status = s5x.s5status_str(status)))
    sys.exit(3)

  iopump.pump(io, (sys.stdin.buffer,sys.stdout.buffer))

def client(host,port,cert=None,key=None,ca=None,tls=False):
  '''Similar to netcat

  :param str host: address to connect
  :param int port: port to connect
  :param bool tls: Enable TLS
  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate
  '''
  sock = s5x.connect_to(host, port)
  if tls:
    context = sslctx.client_context(cert, key, ca)
    sock = context.wrap_socket(sock, server_side=False, server_hostname = sslctx.fixunixname(host))
    logging.debug("SSL established. Peer: {}".format(sock.getpeercert()))

  iopump.pump(sock,[sys.stdin.buffer,sys.stdout.buffer])

