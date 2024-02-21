#!python
"""
Implements enhanced socks5 protocol in python

"""
try:
  from icecream import ic
  ic.configureOutput(includeContext=True)
except ImportError:  # Graceful fallback if IceCream isn't installed.
  ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

import logging
import os
import socket
from enum import IntEnum
from ipaddress import ip_address, IPv4Address
from struct import pack, unpack

from pyus import src


class S5CMD(IntEnum):
  '''Enumeration for SOCKS5 commands'''
  CONNECT = 1
  BIND = 2
  UDPASSOC = 3

class S5STATUS(IntEnum):
  '''Enumeration for SOCKS5 status responses'''
  OK = 0x00
  ERROR = 0x01
  DENIED = 0x02
  NETUNREACH = 0x03
  HOSTUNREACH = 0x04
  CONNREFUSED = 0x05
  TIMEOUT = 0x06
  PROTOERROR = 0x07
  BADADDR = 0x08
  EOF = 0x101

class AUTH(IntEnum):
  '''SOCKS5 Authentication methods'''
  NONE = 0x00
  GSSAPI = 0x01
  BASIC = 0x02 # User/Password
  CHAP = 0x03
  CRAM = 0x05
  SSL = 0x06
  NDSAUTH= 0x07

PROTO_VER = 0x05
'''implemented SOSCKS protocol version'''
HELLO = bytes([PROTO_VER,0x01, 0x00])
'''Initialize SOCKS communications'''
WELCOME = bytes([PROTO_VER, 0x00])
'''Confirm the intialization of communications'''

BUFSIZE = 2048
'''Communications buffer size'''
TIMEOUT_SOCKET = 5
'''Time-out how much time we can spend in protocol transactions'''
DEFAULT_AF = socket.AF_INET
'''Default Address family either IPv4 or IPv6'''

def s5cmd_str(c):
  '''Returns a string represtantion of a SOCKS command code

  :param int c: command code
  :returns str: string version of the code
  '''
  cmd_str = [ None, 'Connect', 'Bind', 'UDPAssoc' ]
  if c < 1 or c >= len(cmd_str): return f'Unknown cmd ({c})'
  return cmd_str[c]

def s5status_str(s):
  '''Returns a string represtantion of a SOCKS status code

  :param int s: status code
  :returns str: string version of the status
  '''
  status_str = [
    'OK', 'General Error', 'Permission Denied', 'Network unreachable',
    'Host unreachable', 'Conection refused', 'Timed out', 'Protocol or Unsupported error',
    'Bad address'
  ]
  if s == S5STATUS.EOF: return 'End of Communications'
  if s < 0 or s >= len(status_str): return f'Unknown status ({s})'
  return status_str[s]


def auth_str(a):
  '''Returns a string represtantion of a SOCKS auth type

  :param int a: auth type code
  :returns str: string version of the auth type
  '''
  aa_str = [ None, 'GSSAPI', 'Basic', 'CHAP', None, 'CRAM', 'SSL', 'NDS Auth' ]
  if a < 0 or a >= len(aa_str) or aa_str[a] is None:
    return f'Unknown auth type ({a})'
  return aa_str[a]



class SocksAddress:
  '''Socks Address'''
  IPv4 = 0x01
  DNS = 0x03
  IPv6 = 0x04
  UNIX = 0x80

  def enc_addr(self):
    ''' Encode a SOCKS5 address
    :returns bytes: encoded byte string
    '''
    if self.type is None: return b'\x00'

    if self.type == SocksAddress.IPv4 or self.type == SocksAddress.IPv6:
      return bytes([self.type]) +  self.addr.packed
    else:
      return bytes([self.type, len(self.addr.encode())]) + self.addr.encode()

  def __init__(self,*args):
    '''Initialize a SocksAddress

    Constructor modes:

    - `SocksAddress()` : Creates a Null address
    - `SocksAddress(str)` : Initializes instance by parsing string
    - `SocksAddress(socket)` : Reads address from socket
    '''

    if len(args) == 0:
      self.type = None # No type defined
      self.addr = None
    elif len(args) == 1:
      if isinstance(args[0],str):
        self.type, self.addr = SocksAddress.parse_addr(args[0])
      elif isinstance(args[0],socket.socket):
        self.type, self.addr = SocksAddress.recv_addr(args[0])
      else:
        raise TypeError(f'Invalid object {args[0]}')
    elif len(args) == 2:
      if isinstance(args[0],bytes):
        self.type, self.addr, bcount = SocksAddress.read_buffer(args[0])
        args[1]['bcount'] = bcount
      else:
        raise TypeError(f'Invalid object {args[0]}')
    else:
      raise TypeError('Function usage error')

  def read_buffer(buf):
    '''Fetch address from buffer

    :param bytes buf: buffer to read
    :returns int,bytes,int: type, address, byte count
    '''
    bcount = 1
    s5type = buf[0]
    if s5type == SocksAddress.IPv4:
      addr = buf[1:5]
      addr = ip_address(addr)
      bcount += 4
    elif s5type == SocksAddress.IPv6:
      addr = buf[1:17]
      addr = ip_address(addr)
      bcount += 16
    elif s5type == SocksAddress.DNS:
      addr = buf[1]
      bcount += addr + 1
      addr = buf[2:2+addr]
      addr = addr.decode() if isinstance(addr,bytes) else addr
    elif s5type == SocksAddress.UNIX:
      addr = buf[1]
      bcount += addr + 1
      addr = buf[2:2+addr]
      addr = addr.decode() if isinstance(addr,bytes) else addr
    else:
      raise ValueError(f'Invalid AddressType: {s5type}')
    return s5type, addr, bcount

  def recv_addr(sock: socket.socket):
    '''Read Socks5 address from a socket

    :param socket.socket sock: Socket for reading
    :returns int,addr: socks5 type, packed address
    '''
    s5type = sock.recv(1)
    s5type = s5type[0]

    if s5type == SocksAddress.IPv4:
      addr = sock.recv(4)
      addr = ip_address(addr)
    elif s5type == SocksAddress.IPv6:
      addr = sock.recv(16)
      addr = ip_address(addr)
      return s5type, addr
    elif s5type == SocksAddress.DNS:
      addr = sock.recv(1)
      addr = sock.recv(addr[0])
      addr = addr.decode() if isinstance(addr,bytes) else addr
    elif s5type == SocksAddress.UNIX:
      addr = sock.recv(1)
      addr = sock.recv(addr[0])
      addr = addr.decode() if isinstance(addr,bytes) else addr
    else:
      raise ValueError(f'Invalid AddressType: {s5type}')
    return s5type, addr

  def parse_addr(host: str):
    '''Identify and parse a host address

    :param str host: string containing address to parse
    :returns int,str: the address type code, and the parsed address
    '''
    try:
      addr = ip_address(host)
      if type(addr) is IPv4Address:
        return SocksAddress.IPv4, addr
      else:
        return SocksAddress.IPv6, addr
    except ValueError:
      ...
    if host.startswith('unix:'):
      return SocksAddress.UNIX, host[5:]
    else:
      return SocksAddress.DNS, host

  def map_s5type(self):
    '''Map s5type to AF
    :returns AF,str: Returns Adress family code, address to use in bind or connect functions
    '''
    match self.type:
      case SocksAddress.IPv4:
        return socket.AF_INET, self.addr.compressed
      case SocksAddress.IPv6:
        return socket.AF_INET6, self.addr.compressed
      case SocksAddress.UNIX:
        return socket.AF_UNIX, self.addr
      case SocksAddress.DNS:
        return DEFAULT_AF, self.addr
      case other:
        raise ValueError(f'Unknown s5type: {self.type}')

  def addr_str(self):
    '''Format address as a string
    :returns str: string representation of address
    '''
    match self.type:
      case SocksAddress.IPv4:
        return self.addr.compressed
      case SocksAddress.IPv6:
        return self.addr.compressed
      case SocksAddress.UNIX:
        return self.addr
      case SocksAddress.DNS:
        return self.addr
      case other:
        raise ValueError(f'Unknown s5type: {self.type}')

  def addrtype_str(a):
    '''Returns a string represtantion of a SOCKS address type

    :param int|self a: address type integer
    :returns str: string version of the address type
    '''
    if isinstance(a,SocksAddress): a = a.type

    atypes_str = [ None, 'IPv4', None, 'DNS', 'IPv6']
    if a == SocksAddress.UNIX: return 'unix'
    if a < 0 or a >= len(atypes_str) or atypes_str[a] is None:
      return f'Unknown Address ({a})'
    return atypes_str[a]


def enc_port(port):
  '''Encode a SOCKS5 port

  :param int port: port number
  :returns bytes: encoded port
  '''
  return bytes([(port>>8)&0xff,port&0xff])

def sendmsg(sock, msg, addr, port):
  ''' Send a socks5 message

  :param socket.socket sock: communications socket
  :param int msg: command or status code to send
  :param SocksAddress addr: Address for the message
  :param int port: port for this message
  '''
  sock.sendall(bytes([PROTO_VER,msg, 0])+ addr.enc_addr() + enc_port(port))

def recvmsg(sock):
  ''' Read a SOCKS5 message

  :param socket.socket sock: communcations oscket
  :returns tuple[int,s5type, str,int]: message, s5type, address, port
  '''
  # +----+-----+-------+------+----------+----------+
  # |VER | MSG |  RSV  | ATYP | DST.ADDR | DST.PORT |
  # +----+-----+-------+------+----------+----------+
  s5req = sock.recv(1024)
  if len(s5req) == 0: return S5STATUS.EOF, None, None
  # ~ ic('Read Bytes',len(s5req),s5req)

  # ~ try:
    # ~ if s5req[0] != PROTO_VER or s5req[2] != 0x00:
      # ~ raise ValueError('Invalid Proto ver or Reserved byte')
  # ~ except IndexError:
    # ~ logging.error(f'Protocol error in {src()}')
    # ~ raise
  if s5req[0] != PROTO_VER or s5req[2] != 0x00:
    raise ValueError('Invalid Proto ver or Reserved byte')

  msg = s5req[1]
  ext = {}
  addr = SocksAddress(s5req[3:],ext)
  port = s5req[3+ext['bcount']:5+ext['bcount']]
  port, = unpack('!H',port)
  return msg, addr, port

def client_handshake(sock):
  '''Perform the client side of the handshake
  :param socket.socket sock: communications socket
  :returns bool: True on success, False on failure
  '''
  sock.sendall(HELLO)
  msg = sock.recv(BUFSIZE)

  return msg == WELCOME

def server_handshake(sock):
  '''Perform the server side of the handshake
  :param socket.socket sock: communications socket
  :returns bool: True on success, False on failure
  '''
  msg = sock.recv(BUFSIZE)
  if msg[0] != PROTO_VER or msg[1] < 1 or not AUTH.NONE in msg[2:]:
    return False
  sock.sendall(WELCOME)
  return True

def bind_port(addr, port):
  """
  Bind the socket to address and
  isten for connections made to the socket

  :param addr: address to bind to
  :param int port: port to listen to
  :returns socket.socket: Returns bound socket.

  When binding UNIX addresses, usually the port is ignored unless
  the socket path already exists, if that is the case if port == 0
  then the socket path will be removed.

  """

  if isinstance(addr,str):
    if addr == '' or addr == '*': addr = '::'
    addr = SocksAddress(addr)

  af, addr = addr.map_s5type()

  sock = socket.socket(af, socket.SOCK_STREAM)
  logging.info(f'Bind {addr}:{port} {src()}')
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  if af == socket.AF_INET6:
    if socket.has_dualstack_ipv6():
      sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

    sock.bind((addr, port, 0, 0))
  elif af == socket.AF_UNIX:
    if port == 0 and os.path.exists(addr):
      os.remove(addr)
    sock.bind(addr)
  else:
    sock.bind((addr, port))
  sock.listen(10)
  return sock

def connect_to(dst_addr, dst_port):
  """ Connect to desired destination
  :param str|SocksAddress dst_addr: destination address
  :param int dst_port: port
  :returns socket.socket: connected socket

  Creates a socket and proceeds to stablish a connection.
  """
  if isinstance(dst_addr,str): dst_addr = SocksAddress(dst_addr)
  af, addr = dst_addr.map_s5type()

  sock = socket.socket(af, socket.SOCK_STREAM)

  sock.settimeout(TIMEOUT_SOCKET)
  if af == socket.AF_INET6:
    sock.connect((addr, dst_port, 0, 0))
  elif af == socket.AF_UNIX:
    sock.connect(addr)
  else:
    sock.connect((addr, dst_port))
  return sock

if __name__ == '__main__':
  ...
  # ~ addr = SocksAddress('127.0.0.1')
  # ~ ic(addr)
  # ~ addr = SocksAddress('localhost')
  # ~ ic(addr)
