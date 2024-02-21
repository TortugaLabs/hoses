#!python
try:
  from icecream import ic
  ic.configureOutput(includeContext=True)
except ImportError:  # Graceful fallback if IceCream isn't installed.
  ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

import os
import sys
import socket
import logging
import logging.config
from argparse import ArgumentParser, Action, Namespace

try:
  sys.path.insert(0,os.path.dirname(__file__))
except NameError:
  ...

import access
import hose
import netcat
import socks5x as s5x
import pyus
from pyus import src
from __meta__ import version as VERSION

def main_listen(ns: Namespace) -> None:
  '''function that implements the "listen" command
  :param Namespace ns:

  Essentially this command is equivalent to `netcat -l -p port`
  '''
  if ns.sockss_server is None:
    netcat.inetd(address = ns.address,
                port = ns.port,
                dest = ns.dest,
                background = ns.background,
                persist = ns.persist,
                cmd = ns.exec,
                cert = ns.cert,
                key = ns.key,
                ca = ns.ca,
                tls = ns.tls)

  else:
    if ns.tls in ('wrap','unwrap'):
      ic(ns.tls)
      logging.error('Can not enable TLS when using SOCKSS proxy')
      sys.exit(1)
    netcat.listener(sockss_server = ns.sockss_server,
                  sockss_port = ns.sockss_port,
                  address = ns.address,
                  port = ns.port,
                  dest = ns.dest,
                  background = ns.background,
                  persist = ns.persist,
                  cert = ns.cert,
                  key = ns.key,
                  ca = ns.ca,
                  cmd = ns.exec)

def main_connect(ns: Namespace) -> None:
  '''function that implements the "connect" command
  :param Namespace ns:

  Essentially this is equivalent to `netcat target port`
  '''
  if ns.sockss_server is None:
    netcat.client(host = ns.target,
                  port = ns.port,
                  cert = ns.cert,
                  key = ns.key,
                  ca = ns.ca,
                  tls = ns.tls)
  else:
    if ns.tls:
      logging.error('Can not enable TLS when using SOCKSS proxy')
      sys.exit(1)
    netcat.connect(sockss_server = ns.sockss_server,
                  sockss_port = ns.sockss_port,
                  target = ns.target,
                  port = ns.port,
                  cert = ns.cert,
                  key = ns.key,
                  ca = ns.ca)


def main_proxy(ns: Namespace) -> None:
  '''function that implements the "proxy" command
  :param Namespace ns:

  This is the main command that implements the SOCKS proxy
  functionality
  '''
  if ns.sockss_server is None:
    logging.error(f'Unable to starts proxy: no sockss address specified {src()}')
    sys.exit(1)

  hose.proxy(sockss_server = ns.sockss_server,
              sockss_port = ns.sockss_port,
              cert = ns.cert,
              key = ns.key,
              ca = ns.ca)


def cli_parse():
  '''Parse command line arguments
  :returns ArgumentParser: command line parser
  '''
  default_proxy_host = None
  default_proxy_port = 9050
  if not (s5x_proxy_env := os.getenv('HOSES_PROXY',None)) is None:
    parts =  s5x_proxy_env.split(':',1)
    if len(parts) == 2:
      default_proxy_port = int(parts[1])
    default_proxy_host = parts[0]

  cli = ArgumentParser(prog='hoses',
                      description='Enhanced socks5 tools')
  cli.add_argument('-4','--ipv4',help='Prefer IPv4 protocol',dest='ipv6',action='store_false')
  cli.add_argument('-6','--ipv6',help='Prefer IPv6 protocol',action='store_true')
  cli.add_argument('-V','--version', action='version', version='%(prog)s '+VERSION)
  cli.add_argument('-S','--sockss-server', help='sockss server name',default=default_proxy_host)
  cli.add_argument('-P','--sockss-port', help='sockss server port',type=int,default=default_proxy_port)
  cli.add_argument('-A','--access', help='access rules specification', default=os.getenv('HOSES_ACCESS_RULES'))
  cli.add_argument('--cert',help='SSL certificate',default=os.getenv('HOSES_TLS_CERT'))
  cli.add_argument('--key',help='SSL Key',default=os.getenv('HOSES_TLS_KEY'))
  cli.add_argument('--ca',help='Certificate Authority',default=os.getenv('HOSES_TLS_CA'))
  cli.add_argument('--log-cfg',help='Configure logging from file',default=os.getenv('HOSES_LOGCFG'))
  cli.add_argument('--log-opt',help='Logging option', action='append')

  cli.set_defaults(func = None)

  sub = cli.add_subparsers()
  client_cmd = sub.add_parser('connect',help='Connect to target')
  client_cmd.add_argument('--tls', help='Connect using TLS (cannot be used with socks proxy)',default=False, action='store_true')
  client_cmd.add_argument('target',help='Target hostname')
  client_cmd.add_argument('port',help='Target port',type=int)
  client_cmd.set_defaults(func = main_connect)

  proxy_cmd = sub.add_parser('proxy',help='Run proxy server')
  proxy_cmd.add_argument('-l','--log',help='Path to audit log file', default=None,dest='audit_log')
  proxy_cmd.set_defaults(func = main_proxy)

  listen_cmd = sub.add_parser('listen',help='Listen for connections')
  listen_cmd.add_argument('--wrap', help='Forwarded connections as TLS connections',default='none', dest='tls', action='store_const',const='wrap')
  listen_cmd.add_argument('--unwrap', help='Forwarded connections as TLS connections',default='none', dest='tls', action='store_const',const='unwrap')

  listen_cmd.add_argument('-p','--persist', help='Persist this binding', action='store_true',default=False)
  listen_cmd.add_argument('-f','--background', help='go to background after connection', action='store_true', default=False)
  listen_cmd.add_argument('--exec',help='Will execute command', action='store_true', default=False)
  listen_cmd.add_argument('address',help='Bind address')
  listen_cmd.add_argument('port',help='Bind port port',type=int)
  listen_cmd.add_argument('dest',help='destination or exec command',nargs='*')

  listen_cmd.set_defaults(func = main_listen)

  return cli

def parse_logging_opts(logopts):
  '''Helper function that translate command line arguments
  into `logging.basicConfig` options.

  :param list logopts: log options from the CLI namespace

  This funciton calls `loging.basicConfig`.
  '''
  if logopts is None or len(logopts) == 0: return False
  opts = {}
  for opt in logopts:
    if '=' in opt:
      k,v = opt.split('=',1)
    elif ':' in opt:
      k,v = opt.split(':',1)
    else:
      opts[opt] = True
      continue

    # Convert fixed constants...
    vv = getattr(logging, v.upper(),None)
    opts[k] = v if vv is None else vv
  logging.basicConfig(**opts)
  return True

if __name__ == '__main__':
  sys.argv = pyus.file_args(sys.argv)
  parse = cli_parse()
  args = parse.parse_args()
  ic(args)
  if args.func is None:
    parse.print_help()
    sys.exit(8)
  if not args.access is None:
    access.ACCESS_RULES = args.access
  if 'audit_log' in args:
    hose.AUDIT_LOG = args.audit_log

  # Configure logging options
  if not parse_logging_opts(args.log_opt) and not args.log_cfg is None:
    logging.config.fileConfig(args.log_cfg)

  logging.debug('{} ({})'.format(args,src()))

  if args.ipv6:
    s5x.DEFAULT_AF = socket.AF_INET6
  args.func(args)

