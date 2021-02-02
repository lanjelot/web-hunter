#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import time
import argparse
import logging
from threading import Thread, active_count
from socket import gethostbyname, gaierror
import requests
import sys

try:
  # python3+
  from urllib.parse import quote, unquote, urlparse
  from io import StringIO
  from html.parser import HTMLParser
except ImportError:
  # python2.6+
  from urllib import quote, unquote
  from urlparse import urlparse
  from cStringIO import StringIO
  from HTMLParser import HTMLParser

formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)7s - %(message)s', datefmt='%H:%M:%S')
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)
logger = logging.getLogger('webhunter')
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def decode_html(s):
  return HTMLParser().unescape(s)

def parse_options(argv):
  usage_str = """%(prog)s options domain
Hunt domain for URLs, subdomains and emails:
    $ %(prog)s -u -s -e example.com

Hunt for emails using only Google, a more specific query, and a valid Cookie to bypass anti-bot captcha:
    $ %(prog)s -e -p google -x 'google|query|-inurl:index.php example.com' -x 'google|headers|Cookie: GDSESS=..' example.com

Hunt for subdomains using only Bing and a specific search:
    $ %(prog)s -s -p bing -x 'bing|query|ip:1.2.3.4' example.com

Both search engines support the filetype operator:
    $ %(prog)s -u -x 'bing,google|query|example.com -filetype:pdf' example.com"""

  parser = argparse.ArgumentParser(prog=argv[0], usage=usage_str)

  parser.add_argument('-u', dest='hunt_url', action='store_true', default=False, help='hunt for URLs')
  parser.add_argument('-s', dest='hunt_subdomain', action='store_true', default=False, help='hunt for subdomains')
  parser.add_argument('-e', dest='hunt_email', action='store_true', default=False, help='hunt for emails')
  parser.add_argument('-p', dest='plugins', metavar='id,id2 ...', help='only run specific plugins (default is to run all plugins, each plugin in a separate thread)')
  parser.add_argument('-x', dest='extra', action='append', metavar='id|param|val', help='use plugin specific parameters')
  parser.add_argument('--debug', dest='debug', action='store_true', default=False, help='print debugging information')

  parser.add_argument('url', help='specify the domain to search')

  # TODO to implement...
  #parser.add_option('-l', dest='pluginlist', action='store_true', help='list all available plugins')
  #parser.add_option('-q', dest='pluginusage', metavar='id', help='display plugin usage')

  args = parser.parse_args(argv[1:])
  if not (args.hunt_url or args.hunt_subdomain or args.hunt_email):
    parser.error('Missing required option')
  if not args.url:
    parser.error('Missing required argument')

  return args, args[0]

class BasePlugin(Thread):
  def __init__(self, domain, extra, hunt_url, hunt_subdomain, hunt_email):
    Thread.__init__(self)
    self.daemon = True

    self.domain = domain
    self.extra = extra

    self.hunt_url = hunt_url
    self.hunt_subdomain = hunt_subdomain
    self.hunt_email = hunt_email

    self.rr = {}

    logger.debug('extra: %s' % extra)

  @staticmethod
  def pprint_generic(t, l):
    print ("%s %s" % ('-' * (69-len(t)), t))
    print ('\n'.join(set(l)))
    print ('\n')

  @staticmethod
  def pprint_dic(title, dic, fmt):
    print ("%s %s" % ('-' * (69-len(title)), title))
    for k in dic.keys():
      l = dic[k]
      first = True
      for v in l:
        if first:
          print (fmt % (k, v))
          first = False
        else:
          print (fmt % ('', v))

  @staticmethod
  def pprint_email(emails, title='Emails'):
    rr = {}
    for email in set(emails):
      rcpt, dom = re.match(r'(.+?)(@.+)$', email).groups()
      if dom not in rr: rr[dom] = []
      rr[dom].append(rcpt)

    BasePlugin.pprint_dic(title, rr, '%40s %s')


  @staticmethod
  def pprint_subdomain(subdomains, title='Subdomains'):
    rr = {}
    for domain in set(subdomains):
      scheme, hostname = re.match(r'(\w+)://([^/]*.+(?::[\d\w]+)?)/$', domain, re.I).groups()
      try:
        ip = gethostbyname(hostname.split(':')[0])
      except gaierror:
        ip = 'nxdomain'
      if ip not in rr: rr[ip] = []
      rr[ip].append('%-5s %30s' % (scheme, hostname))

    BasePlugin.pprint_dic(title, rr, '%16s %s')

  @staticmethod
  def pprint_url(urls, title='URLs'):
    stats = {} # {'www.dom.com': {'/cms': ('/cms/search.aspx', '/cms/home.php', ...), '/admin': ('/admin/index.html', ...)}, 'ftp.dom.com': ...
    for url in urls:
      (scheme, netloc, path, params, query, fragment) = urlparse(url)
      key = '%s://%s' % (scheme, netloc)
      if key not in stats: stats[key] = {}

      if path.count('/') == 1:
        pdir = '/'
      else:
        pdir = path[:path.rindex('/')]

      if pdir not in stats[key]:
        stats[key][pdir] = []
      stats[key][pdir].append(url)

    print ('%s%s' % ('-' * (69-len(title)), title))
    for key in sorted(stats.keys()):
      dic = stats[key]
      for pdir in sorted(dic.keys()):
        urls = dic[pdir]
        print ('%s%s' % (key, pdir))
        print ('\n'.join(sorted(set(urls))))
        print ('\n')

def remove_tags(l):
  return map(lambda a: re.sub(r'<[^>]+>', '', a), l)

class BaseSE(BasePlugin):
  def __init__(self, domain, extra, hunt_url, hunt_subdomain, hunt_email):
    BasePlugin.__init__(self, domain, extra, hunt_url, hunt_subdomain, hunt_email)

    target_conf = {} # {'url': 'site:example.com', ...}
    for k in all_targets:
      if hasattr(self, 'hunt_%s' % k) and getattr(self, 'hunt_%s' % k):
        target_conf[k] = getattr(self, 'dft_%s' % k)()

    self.headers =  {}
    if 'headers' in extra:
      k, v = extra['headers'].split(':', 1)
      self.headers[k.strip()] = v.strip()

    if 'query' in extra:
      for k in target_conf:
        target_conf[k] = extra['query']

    if 'maxpages' in extra:
      self.maxpages = int(extra['maxpages'])

    self.hunt_conf = {} # {'site:example.com': ('url': re_func, ...), 'example.com': ...}
    for k in target_conf.keys():
      q = target_conf[k]
      re_func = getattr(self, 're_%s' % k)()

      if q not in self.hunt_conf: self.hunt_conf[q] = []
      self.hunt_conf[q].append((k, re_func))
      self.rr[k] = []

  def fetch(self, url, headers={"User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win32; x86; Trident/5.0)"}):
    h = requests.get(url, headers=headers)
    return h.status_code, h.text

  def run(self):
    for query in self.hunt_conf.keys():
      regs = self.hunt_conf[query]
      for html in self.request(query):
        for k, r in regs:
          self.rr[k].extend(r.findall(html))

    # postprocess
    for k in self.rr.keys():
      v = self.rr[k]
      if hasattr(self, 'post_%s' % k):
        self.rr[k] = getattr(self, 'post_%s' % k)(v)

  def dft_url(self):
    return 'site:%s' % self.domain

  def dft_subdomain(self):
    return 'site:%s' % self.domain

  def dft_email(self):
    return '@%s' % self.domain

  def re_url(self):
    return re.compile(r'href="(\w+://(?:[^/]+\.)?%s(?::[\d\w]+)?/.*?)"' % self.domain, re.I)

  def re_subdomain(self):
    return re.compile(r'(\w+://[^/]*%s(?::[\d\w]+)?/)' % self.domain, re.I)

  def re_email(self):
    return re.compile(r'([\w.+-]+@.+?%s)' % self.domain.split('.')[-1], re.I) # gets more emails but still buggy

  def post_email(self, emails):
    return [e for e in remove_tags(emails) if e.endswith(self.domain)]

  def post_subdomain(self, subdomains):
    return remove_tags(subdomains)

  def post_url(self, urls):
    return [u.replace('&amp;', '&') for u in remove_tags(urls)]

class GoogleSE(BaseSE):
  # asking beyond page 9 gives warning page "Google does not serve more than 1000 results for any query"
  maxpages = 10

  def re_url(self):
    return re.compile(r'href="(\w+://(?:[^/]+\.)?%s(?::[\d\w]+)?/[^"]*)' % self.domain, re.I)

  def post_url(self, urls):
    return [decode_html(u) for u in urls]

  def __init__(self, domain, extra=None, hunt_url=True, hunt_subdomain=True, hunt_email=True):
    BaseSE.__init__(self, domain, extra, hunt_url, hunt_subdomain, hunt_email)

    self.headers = {'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:21.0) Gecko/20100101 Firefox/21.0',
                    'Cookie':'PREF=ID=5abdaf154fc78f7c:U=1f4663bf92fa3ef4:FF=0:LD=en:NR=100:TM=1374631009:LM=1374631113:SG=2:S=m-6Z3KHy4YZgHaZ6'}


  def request(self, query):
    for page_idx in range(self.maxpages):
      url = 'https://www.google.com/search?q=%s&hl=en&num=100&sa=N&filter=0&start=%d' % (quote(query.strip()), page_idx * 100)
      logger.debug('Google: %s' % url)
      code, data = self.fetch(url, self.headers)

      if code != 200:
        raise Exception('HTTP error: %d' % code)

      yield data

      open('/tmp/google_page_%d' % page_idx, 'w').write(data)

      if 'Next</span></a>' not in data:
        break

class BingSE(BaseSE):

  maxpages = 100

  def __init__(self, domain, extra=None, hunt_url=True, hunt_subdomain=True, hunt_email=True):
    BaseSE.__init__(self, domain, extra, hunt_url, hunt_subdomain, hunt_email)

  def request(self, query):
    self.headers = {'User-Agent':' Mozilla/5.0', # or maybe use msnbot User-Agent: 'msnbot/1.1 (+http://search.msn.com/msnbot.htm)'
                    'Host':'www.bing.com',
                    'Accept-Language':'en-us,en'} # we need the Next button in English

    # either stop after too many pages or after the Next button disappears
    btn_next = 'Next</div></a></li>'

    page_idx = 0
    stop = False

    while not stop:
      uri =  '/search?q=%s&first=%s' % (quote(query.strip()), (page_idx * 10) + 1)
      logger.debug('Bing: %s' % uri)
      code, data = self.fetch('http://www.bing.com' + uri, self.headers)

      if code != 200:
        raise Exception('HTTP error: %d' % code)

      page_idx += 1
      if btn_next not in data or page_idx > self.maxpages:
        stop = True

      yield data

all_plugins = {'google': GoogleSE, 'bing': BingSE}
all_targets = ['url', 'subdomain', 'email']

def main():
  args = parse_options(sys.argv)
  domain = args.url

  if args.debug: logger.setLevel(logging.DEBUG)

  plugin_extra = {} # {'google': {'headers': 'Cookie': ...', 'query': '...'}, 'bing': ...}
  for pid in all_plugins:
    plugin_extra[pid] = {}

  if args.extra:
    for extra in args.extra:
      pids, param, val = extra.split('|')
      for pid in pids.split(','):
        plugin_extra[pid].update({param: val})

  run_plugins = {}
  for k in all_plugins.keys():
    v = all_plugins[k]
    if not args.plugins or k in args.plugins.split(','):
      run_plugins[k] = v

  plugins = []
  for pid in run_plugins.keys():
    klass = run_plugins[pid]
    extra = plugin_extra[pid]

    p = klass(domain, extra, hunt_url=args.hunt_url, hunt_subdomain=args.hunt_subdomain, hunt_email=args.hunt_email)
    p.start()
    plugins.append(p)

  while active_count() > 1:
    time.sleep(0.5)

  all_rr = {}
  for p in plugins:
    for k in p.rr.keys():
      v = p.rr[k]
      if k not in all_rr: all_rr[k] = []
      all_rr[k].extend(v)

  for k in all_rr.keys():
    v = all_rr[k]
    getattr(BasePlugin, 'pprint_%s' % k)(v)


if __name__ == '__main__':
  main()

# vim: ts=2 sw=2 sts=2 et
