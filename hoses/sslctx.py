#!python
try:
  from icecream import ic
  ic.configureOutput(includeContext=True)
except ImportError:  # Graceful fallback if IceCream isn't installed.
  ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

import os
import ssl


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
  context.minimum_version = ssl.TLSVersion.TLSv1_3
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
  context.minimum_version = ssl.TLSVersion.TLSv1_3
  return context

def fixunixname(s):
  '''Fix UNIX's socket names

  :param str s: server_hostname string to be normalized
  :returns str: normalized string

  Takes the input string and if it is a UNIX socket address returns
  the last component of the  path.
  '''
  if not s.startswith('unix:'): return s
  return 'unix:' + os.path.basename(s[5:])


def flatten_dn(dn):
  '''Simplify a X509 distinguished name

  :param tuple dn: tuples containing dn info
  :returns dict: dict containing attr keys
  '''
  kvs = {}
  for comp in dn:
    for k,v in comp:
      if k in kvs:
        if isinstance(kvs[k],list):
          kvs[k].append(v)
        else:
          kvs[k] = [ kvs[k], v ]
      else:
        kvs[k] = v

  return kvs

def strfy(dn,item = None):
  '''Convert the DN dict or its components into a single string

  :param dict dn: DN dictionary
  :param str item|None: If not None, a single item to convert to string
  '''
  if item is None:
    tx = ''
    for k,v in sorted(dn.items()):
      if isinstance(v,list):
        for c in v:
          tx += f'/{k}={c}'
      else:
        tx += f'/{k}={v}'
    return tx


  if not item in dn: return ''
  if isinstance(dn[item],list):
    return '/'.join(dn[item])
  else:
    return dn[item]


# : and ; as path separators = for KV separator

