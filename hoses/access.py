#python
'''
Access rules module

Access checks can use of the following variables:

- `host` : current host running the proxy
- Remote host variables:
  - `client`
  - `client_*` individual attributes
- Subject variables:
  - `subject` all compoments as a single string
  - `subj_commonName`
  - `subj_*` other subject components specified in the certificate
- Request variables:
  - `s5req_cmd` : SOCKS command as a string (`Connect`, `Bind`, `UDPAssoc`)
  - `s5req_cmd_code` : Request command code
  - `s5req_addrtype` : SOCKS address type as a string (`IPv4`, `DNS`, `IPv6`, `unix`)
  - `s5req_addrtype_code` : SOCKS address type code
  - `s5req_address` : network address
  - `s5req_port : network port

For URLs, these can be referred using `{var}` substitutions.  For
external commands these are passed as environment variables.

```
allow|deny,[!]{host},{client},{subject},{s5req_cmd},{s5req_addrtype},{s5req_address},{s5req_port}'
```

'''
try:
  from icecream import ic
  ic.configureOutput(includeContext=True)
except ImportError:  # Graceful fallback if IceCream isn't installed.
  ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

import fnmatch
import json
import logging
import os
import platform
import requests
import select
import subprocess

import pyus
import sslctx
import unixcreds
from pyus import src

ACCESS_RULES = None
HOSTNAME = platform.node()
RULE_TARGETS = {
  'allow': True,
  'permit': True,
  'deny': False,
  'block': False,
}
ACCESS_PIPE_CTX = { }
TIMEOUT = 5
RULE_FORMAT = '{host},{client},{subject},{s5req_cmd},{s5req_addrtype},{s5req_address},{s5req_port}'

class SafeDict(dict):
  def __missing__(self,key):
    return '(none)'

def process_rules(rules, req, envars, fmtvars, current):
  '''Process rules either from file, script or http[s] request
  :param str fname: file to process
  :param dict req: request data to send to remote API
  :param dict envvars: variables to use in process runs
  :param SafeDict fmtvars: variables used for expansions
  :param str current: current value to match rules against
  :returns bool|None: rule decision
  '''
  if rules.startswith('http://') or rules.startswith('https://'):
    resp = requests.post(rules.format_map(fmtvars), json = req)
    if resp.status_code != 200: # Web server didn't like that request
      logging.error(f'Error http request: {rules}.  Status: {resp.status_code}. {src()}')
      return None
    ruletxt = resp.text
  elif not os.path.exists(rules):
    logging.error(f'{rules}: rule set not found {src()}')
    return False
  elif os.access(rules,os.X_OK):
    rc = subprocess.run(rules,capture_output=True,text=True,env=envars)
    if rc.returncode != 0:
      logging.error(f'Error running {rules}.\n{rc.stderr}\n{src()}')
      return None
    ruletxt = rc.stdout
  else:
    ruletxt = pyus.readfile(rules)

  # Evaluate rules...
  resp = ruletxt.strip().lower()
  if resp in RULE_TARGETS: return RULE_TARGETS[resp]

  for rn in rules.splitlines():
    if (i:=rn.find('#')) != -1: rn = rn[:i]
    if (rn:=rn.strip()) == '': continue
    rn = rn.lower()
    if ',' in rn:
      rn, expr = rn.split(',')
      rn = rn.strip()
      expr = expr.strip()
      op = ''
      if expr.startswith('!'):
        op = '!'
        expr = expr[1:].strip()

      if fnmatch.fnmatch(current, expr):
        if op == '!': continue
      else:
        if op != '!': continue

    # Rule match!

    if rn in RULE_TARGETS: return RULE_TARGETS[rn]
    if not (rn.startswith('http://') or rn.startswith('https://')):
      rn = os.path.join(os.path.dirname(rules), rn)
    resp = process_rules(rn, req, envars, fmtvars, current)
    if resp is None: continue
    return resp

  # No rule matched
  return None

def access_pipe(cmd, req):
  '''Check permissions using a command pipe

  :param str cmd: Command to execute to start the pipe
  :param dict req: dict containing client, subject, s5req values.
  :returns bool: True or false depending on the pipe response

  Command reads requests one per line.  Requests are in json format.
  It shoud output "allow" or "deny" in a single line.
  '''
  for attempt in range(5):
    if not 'cmd' in ACCESS_PIPE_CTX:
      ACCESS_PIPE_CTX['cmd'] = subprocess.Popen(cmd,
                        shell=True,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        text=True)
    try:
      ACCESS_PIPE_CTX['cmd'].stdin.write(json.dumps(req).replace('\n',' ')+'\n')
      ACCESS_PIPE_CTX['cmd'].stdin.flush()

      rd,_,_ = select.select([ACCESS_PIPE_CTX['cmd'].stdout],[],[],TIMEOUT)
      if not ACCESS_PIPE_CTX['cmd'].stdout in rd:
        logging.warning(f'Pipe request timed out! {src()}')
        ACCESS_PIPE_CTX['cmd'].stdin.close()
        del(ACCESS_PIPE_CTX['cmd'])
        continue

      resp = ACCESS_PIPE_CTX['cmd'].stdout.readline().strip().lower()
      if resp in RULE_TARGETS:
        return RULE_TARGETS[resp]
      logging.info(f'Pipe returned {resp} at {src()}')
      return False
    except BrokenPipeError:
      del(ACCESS_PIPE_CTX['cmd'])
  logging.error(f'{cmd}: failed to spawn at {src()}')
  return False

def check_access(client, subj,s5req):
  '''
  Check ACCESS_LIST configuration and evaluate for access permissions

  :param dict client: Dictionary containing client attributes
  :param dict subj: Dictionary containing subject attributes
  :param dict s5req: Dictionary containing request parameters
  :returns bool: returns True if access is allowed, False, if denied
  '''
  if ACCESS_RULES is None: return True # Allow everything by default

  req = {'client':client,'subject':subj,'s5req':s5req,'host':HOSTNAME,}

  if ACCESS_RULES.startswith('|'):
    # Run the given command
    # run command sending line items
    return access_pipe(ACCESS_RULES[1:],req)

  if not (ACCESS_RULES.startswith('http://') or ACCESS_RULES.startswith('https://') or os.path.exists(ACCESS_RULES)):
    logging.error(f'{ACCESS_RULES}: rule set not found {src()}')
    return False

  # Flatten vars and use current environment
  envars = os.environ.copy()
  envars['host'] = HOSTNAME
  for k,v in s5req.items():
    envars[f's5req_{k}'] = str(v)
  if subj is None:
    envars['subject'] = '(none)'
  else:
    envars['subject'] = sslctx.strfy(subj)
    for k in subj:
      envars[f'subj_{k}'] = sslctx.strfy(subj,k)
  if client['type'] == 'UNIX':
    envars['client'] = unixcreds.strfy(client)
    for k in client:
      envars[f'client_{k}'] = unixcreds.strfy(client,k)
  else:
    envars['client'] = '|'.join([client['type'],client['addr'],client['port']])
    for k,v in client.items():
      envars[f'client_{k}'] = str(v)
  # no commas
  fmtvars = SafeDict()
  for k in envars:
    fmtvars[k] = envars[k].replace(',',' ')

  current = RULE_FORMAT.format_map(fmtvars).lower()

  resp =  process_rules(ACCESS_RULES, req, envars, fmtvars, current)
  return False if resp is None else resp


if __name__ == '__main__':
  print(HOSTNAME)

  print('Enter an empty line to quit')
  while pat := input('pattern> '):
    resp = access_pipe('python3 __main__.py connect localhost 9999', { 'pat':pat })
    print(pat,resp)




