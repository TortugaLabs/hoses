#!python
import socket
import socks5x as s5x
import iopump
import sys
from threading import Thread, active_count
import errno
import select
import subprocess
import pyus
from pyus import src
import shlex
import os
import signal
import ssl
import socket
import access
import logging


def client_context(cert, key, ca):
  '''Create a SSL client context
  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate
  :returns SSL context|None:

  If no CA is provided, it will return None
  If no cert is specified, then the client will not authenticate
  to the server.
  '''
  if ca is None: return None
  context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
  if not cert is None:
    context.load_cert_chain(cert,key)
  return context

def server_context(cert, key, ca):
  '''Create a SSL server context
  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate
  :returns SSL context|None:

  If no cert is specified, then no SSL will be performed.
  If no CA is provided, then client certificates will NOT be validated.
  '''
  if cert is None: return None
  if ca is None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  else:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca)
  context.load_cert_chain(cert,key)
  return context


def serve_client(sock):
  '''Serve a SOCKS proxy client connection

  :param socket.socket sock: socket of proxy client

  Will perform SOCKS protocol functionality.
  '''
  
  sock.settimeout(s5x.TIMEOUT_SOCKET)
  if not s5x.server_handshake(sock):
    logging.error(f'Handshake error {src()}')
    sock.close()
    return

  cmd, s5type, addr, port = s5x.recvmsg(sock)
  print(addr)
  #
  # Rules can only be evaluted with SSL enabled
  if not ((getattr(sock, 'getpeercert',None) is None) or (access.ACCESS_RULES is None)):
    peercert = sock.getpeercert()
    subj = dict(x[0] for x in peercert['subject'])
    s5req = {
      'cmd': s5x.s5cmd_str(cmd),
      'cmd_code': cmd,
      'addrtype': s5x.addrtype_str(s5type),
      'addrtype_code': s5type,
      'address': addr,
      'port': port,
    }
    logging.debug(f'Subject: {subj} ({src()})')
    logging.debug(f'Subject: {s5req} ({src()})')
    if not access.check_access(subj, s5req):
      s5x.sendmsg(sock, s5x.S5STATUS.DENIED, (s5type,addr), port)
      sock.close()
      return

  if cmd == s5x.S5CMD.CONNECT:
    logging.info(f'connect_to {addr}:{port} ({src()})')
    try:
      target = s5x.connect_to((s5type, addr),port)
    except OSError as e:
      code = s5x.S5STATUS.ERROR
      if e.errno == errno.ENETUNREACH:
        code = s5x.S5STATUS.NETUNREACH
      elif e.errno == errno.EHOSTUNREACH:
        code = s5x.S5STATUS.HOSTUNREACH
      elif e.errno == errno.ECONNREFUSED:
        code = s5x.S5STATUS.CONNREFUSED
      elif e.errno == errno.ETIMEDOUT:
        code = s5x.S5STATUS.TIMEOUT
      else:
        logging.error(f'Unhandled error {e} ({src()})')

      s5x.sendmsg(sock, code, (s5type,addr), port)
      sock.close()
      return
    s5x.sendmsg(sock, s5x.S5STATUS.OK, addr, port)
    iopump.pump(sock, target)
    logging.info(f'Disconnected ({src()}))')
  elif cmd == s5x.S5CMD.BIND:
    try:
      listener = s5x.bind_port((s5type, addr),port)
    except OSError as e:
      code = s5x.S5STATUS.ERROR
      if e.errno == errno.EADDRINUSE:
        code = s5x.S5STATUS.BADADDR
      else:
        logging.error(f'Unhandled error {e} ({src()})')
      s5x.sendmsg(sock, code, (s5type,addr), port)
      sock.close()
      return

    while True:
      readers, _, _ = select.select([sock, listener], [], [], None)
      if sock in readers:
        # If we receive anything at this point, it is an error
        # so we close connection
        logging.debug(f'Listener client gone ({src()})')
        listener.close()
        sock.close()
        return
      if listener in readers:
        newclient,peer = listener.accept()
        break

    logging.debug(f'{peer} ({src()})')
    listener.close()

    s5x.sendmsg(sock, s5x.S5STATUS.OK, (s5type,addr), port)
    iopump.pump(sock, newclient)
    logging.info(f'Disconnected ({src()}))')
  elif cmd == s5x.S5CMD.UDPASSOC:
    logging.error(f'Request unipmeneted UDPASSOCIATE ({src()})')
    s5x.sendmsg(sock, s5x.S5STATUS.PROTOERROR, addr, port)
    sock.close()
  else:
    logging.error(f'Request unknown command ({src()})')
    s5x.sendmsg(sock, s5x.S5STATUS.PROTOERROR, addr, port)
    sock.close()

def local_server(peer, dest = [], background = False, cmd = False):
  '''netcat listener handler

  :param socket.socket peer: incoming client
  :param list dest: destination target
  :param bool background: process should go to the background upon connect
  :param bool cmd: destination target is a command

  Create a IO channel to the target and starts communicating with it.
  '''
  if len(dest) == 0:
    iopump.pump(peer, (sys.stdin,sys.stdout))
    return

  if background:
    pyus.daemonize()
    pyus.null_io()

  if cmd:
    if len(dest) == 1:
      command = dest[0]
      if len(shlex.split(command)) > 0: shell = True
    else:
      command = dest
      shell = False
    proc = subprocess.Popen(command, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    logging.debug(f'{proc} ({src()})')
    iopump.pump(peer, (proc.stdout,proc.stdin))
    return

  s5type, addr = s5x.parse_addr(dest[0])
  if s5type == s5x.ADDRTYPE.UNIX:
    sock = s5x.connect_to(ns.dest[0],0)
  elif len(dest) != 2:
    logging.error('Must specify {host} {port} values')
    return
  else:
    sock = s5x.connect_to(ns.dest[0], int(ns.dest[1]))
  iopump.pump(peer, sock)


def inetd(address, port, dest, background, persist, cmd):
  ''' Wait for a incoming connection and exec process or tunnel to target

  :param str address: address to listen on
  :param int port: port to listen on
  :param bool persist: normally it will accept one connection and exit, if persist is true, it will accept multiple connections.
  :param list dest: destination target
  :param bool background: process should go to the background upon connect
  :param bool cmd: destination target is a command
  
  '''
  listener = s5x.bind_port(address,port)
  signal.signal(signal.SIGCHLD, pyus.reap_child_proc)

  if len(dest) == 0:
    if background:
      logging.error('Background option not compatible with empty destination (ignored)')
    if ns.persist:
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

  logging.info(f'Connected {peer} ({src()})')
  listener.close()
  local_server(sock, dest=dest, background = background, cmd = cmd)

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

  context = client_context(cert, key, ca)

  while True:
    io = s5x.connect_to(sockss_server,sockss_port)
    if not context is None:
      io = context.wrap_socket(io, server_side=False, server_hostname = sockss_server)
      logging.debug("SSL established. Peer: {}".format(io.getpeercert()))
    if not s5x.client_handshake(io):
      logging.error('Protocol error during handshake')
      sys.exit(1)

    s5x.sendmsg(io, s5x.S5CMD.BIND, address, port)
    io.settimeout(None)
    status, s5type, addr, port = s5x.recvmsg(io)
    if status != s5x.S5STATUS.OK:
      logging.error('Sockss5 proxy error: {status}\n'.format(status = s5x.s5status_str(status)))
      sys.exit(3)
    if not persist: break

    newpid = os.fork()
    if newpid == 0:
      break
    else:
      io.close()

  local_server(io, dest=dest, background=background, cmd=cmd)

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
  context = client_context(cert, key, ca)
  io = s5x.connect_to(sockss_server,sockss_port)
  if not context is None:
    io = context.wrap_socket(io, server_side=False, server_hostname = sockss_server)
    logging.debug("SSL established. Peer: {}".format(io.getpeercert()))

  if not s5x.client_handshake(io):
    logging.error('Protocol error during handshake');
    sys.exit(1)

  s5x.sendmsg(io, s5x.S5CMD.CONNECT, target, port)
  status, s5type, addr, port = s5x.recvmsg(io)
  if status != s5x.S5STATUS.OK:
    logging.error('Sockss5 proxy error: {status}\n'.format(status = s5x.s5status_str(status)))
    sys.exit(3)

  iopump.pump(io, (sys.stdin,sys.stdout))

def netcat(host,port):
  '''Similar to netcat

  :param str host: address to connect
  :param int port: port to connect

  '''
  sock = s5x.connect_to(host, port)
  iopump.pump(sock,[sys.stdin,sys.stdout])

def proxy(sockss_server, sockss_port, cert,key, ca):
  """ Main function
  :param str sockss_server: SOCKS proxy server address
  :param int sockss_port: SOCKS proxy server port
  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate

  This function implements the SOCKS proxy functionality.
  
  """
  context = server_context(cert, key, ca)

  listener = s5x.bind_port(sockss_server, sockss_port)
  while True:
    io, peer = listener.accept()
    if not context is None:
      io = context.wrap_socket(io, server_side=True)
      logging.debug("SSL established. Peer: {}".format(io.getpeercert()))

    logging.info(f'Client: {peer} connected')
    recv_thread = Thread(target=serve_client, args=(io, ))
    recv_thread.start()
