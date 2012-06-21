#!/usr/bin/python
# -*- coding: utf-8 -*-

import httplib
import re
import sys
from time import sleep
from urllib import quote, unquote
from urllib import urlencode
from urlparse import urlparse
from optparse import OptionParser
import logging
from threading import Thread, active_count
import urllib2
from cookielib import CookieJar
from socket import gethostbyname, gaierror

formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)7s - %(message)s', datefmt='%H:%M:%S')
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)
logger = logging.getLogger('webhunter')
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def parse_options(argv):
  usage_str = "usage: %prog options domain\n\n" \
    "Hunt domain for URLs, subdomains and emails:\n" \
    "$ %prog -u -s -e example.com\n\n" \
    "Hunt for emails using only Google, a more specific query, and a valid Cookie to bypass anti-bot captcha:\n" \
    "$ %prog -e -p google -x 'google|query|-inurl:index.php example.com' -x 'google|headers|Cookie: GDSESS=..' example.com\n\n" \
    "Hunt for subdomains using only Bing and a specific search:\n" \
    "$ %prog -s -p bing -x 'bing|query|ip:1.2.3.4' example.com\n\n" \
    "Both plugins support the filetype operator:\n" \
    "$ %prog -u -x 'bing,google|query|example.com -filetype:pdf' example.com"

  parser = OptionParser(usage=usage_str)

  parser.add_option('-u', dest='hunt_url', action='store_true', default=False,
    help='hunt for URLs')
  parser.add_option('-s', dest='hunt_subdomain', action='store_true', default=False,
    help='hunt for subdomains')
  parser.add_option('-e', dest='hunt_email', action='store_true', default=False,
    help='hunt for emails')

  parser.add_option('-l', dest='pluginlist', action='store_true',
    help='list all available plugins')
  parser.add_option('-p', dest='plugins', metavar='id,id2 ...',
    help='only run given plugins (default is to run all of them)')

  parser.add_option('-q', dest='pluginusage', metavar='id',
    help='display plugin usage')
  parser.add_option('-x', dest='extra', action='append', metavar='id|param|val',
    help='use plugin specific parameters')

  parser.add_option('--debug', dest='debug', action='store_true', default=False, 
    help='print debugging information')

  (opts, args) = parser.parse_args(argv)
  if not (opts.hunt_url or opts.hunt_subdomain or opts.hunt_email):
    parser.error('Missing required option')
  if not args:
    parser.error('Missing required argument')
  return opts, args[0]

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
    print '-' * (69-len(t)), t
    print '\n'.join(set(l))
    print

  @staticmethod
  def pprint_dic(title, dic, fmt):
    print '-' * (69-len(title)), title
    for k, l in dic.iteritems():
      first = True
      for v in l:
        if first:
          print fmt % (k, v)
          first = False
        else:
          print fmt % ('', v)

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
    for url in set(subdomains):
      scheme, hostname = re.match(r'(https?)://(.+?)/?$', url).groups()
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
        
    print '-' * (69-len(title)), title
    for key, dic in sorted(stats.iteritems()):
      for pdir, urls in sorted(dic.iteritems()):
        print '%s%s' % (key, pdir)
        print '\n'.join(sorted(set(urls)))
        print

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
    for k, q in target_conf.iteritems():
      re_func = getattr(self, 're_%s' % k)()

      if q not in self.hunt_conf: self.hunt_conf[q] = []
      self.hunt_conf[q].append((k, re_func))
      self.rr[k] = []

  def run(self):
    for query, regs in self.hunt_conf.iteritems():
      for html in self.request(query):
        for k, r in regs:
          self.rr[k].extend(r.findall(html))

    # postprocess
    for k, v in self.rr.iteritems():
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
    #return re.compile(r'([\w.+-]+@\S+?%s)' % self.domain.split('.')[-1], re.I)
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
    return re.compile(r'href="/url\?q=(\w+://(?:[^/]+\.)?%s(?::[\d\w]+)?/.*?)(?:%%2B|&amp)' % self.domain, re.I)

  def post_url(self, urls):
    return [unquote(u) for u in remove_tags(urls)]

  def __init__(self, domain, extra=None, hunt_url=True, hunt_subdomain=True, hunt_email=True):
    BaseSE.__init__(self, domain, extra, hunt_url, hunt_subdomain, hunt_email)

  def request(self, query):
    headers = {'User-Agent': useragent_googlebot, # googlebot is less likely to get banned
               'Host': 'www.google.com',}

    if self.headers:
      headers.update(self.headers)

    proxies = {} #{'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'} # debug
    opener = urllib2.build_opener(urllib2.ProxyHandler(proxies))
    opener.addheaders = headers.items()

    for page_idx in range(self.maxpages):
      # query string sent by the advanced search form
      uri = '/search?q=%s&hl=en&num=100&lr=&ft=i&cr=&safe=images&filter=0&start=%d' % (quote(query.strip()), page_idx * 100)
      logger.debug('Google: %s' % uri)
      r = opener.open('http://www.google.com' + uri)

      if r.code != 200:
        raise Exception('HTTP error: %d %s' % (r.code, r.msg))

      yield r.read()

class BingSE(BaseSE): 
  maxpages = 100
  def __init__(self, domain, extra=None, hunt_url=True, hunt_subdomain=True, hunt_email=True):
    BaseSE.__init__(self, domain, extra, hunt_url, hunt_subdomain, hunt_email)

  def request(self, query):
    headers = {'User-Agent': 'Mozilla/5.0',
               'Host': 'www.bing.com',
               'Accept-Language': 'en-us,en'} # we need the Next button in English
    if self.headers:
      headers.update(self.headers)

    proxies = {} #{'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'} # debug
    cjar = CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cjar), urllib2.ProxyHandler(proxies))
    opener.addheaders = headers.items()

    # either stop after too many pages or after the Next button disappears
    btn_next = 'Next</a></li></ul></div><form action="search" id="sb_form2"'

    page_idx = 0
    stop = False
    while not stop:
      uri =  '/search?q=%s&first=%s' % (quote(query.strip()), (page_idx * 10) + 1)
      logger.debug('Bing: %s' % uri)
      r = opener.open('http://www.bing.com' + uri)

      # bypass anti-bot protection
      for c in cjar:
        if c.name == 'OrigMUID':
          ig, cid = c.value.split('%2c')
          uri = '/fd/ls/GLinkPing.aspx?CM=TMF&IG=%s&CID=%s' % (ig, cid)

          logger.debug('Bing: %s' % uri)
          opener.open('http://www.bing.com' + uri)
          break

      if r.code != 200:
        raise Exception('HTTP error: %d %s' % (r.code, r.msg))
      html = r.read()

      page_idx += 1
      if btn_next not in html or page_idx > self.maxpages: 
        stop = True

      yield html

useragent_googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
useragent_msnbot = 'msnbot/1.1 (+http://search.msn.com/msnbot.htm)'

all_plugins = {'google': GoogleSE, 'bing': BingSE}
all_targets = ['url', 'subdomain', 'email']

def main():
  opts, domain = parse_options(sys.argv[1:])
  if opts.debug: logger.setLevel(logging.DEBUG)

  plugin_extra = {} # {'google': {'headers': 'Cookie': ...', 'query': '...'}, 'bing': ...}
  for pid in all_plugins:
    plugin_extra[pid] = {}

  if opts.extra:
    for extra in opts.extra:
      pids, param, val = extra.split('|')
      for pid in pids.split(','):
        plugin_extra[pid].update({param: val})

  run_plugins = {}
  for k, v in all_plugins.iteritems():
    if not opts.plugins or k in opts.plugins.split(','):
      run_plugins[k] = v
  
  plugins = []
  for pid, klass in run_plugins.iteritems():
    extra = plugin_extra[pid]

    p = klass(domain, extra, hunt_url=opts.hunt_url, hunt_subdomain=opts.hunt_subdomain, hunt_email=opts.hunt_email)
    p.start()
    plugins.append(p)

  while active_count() > 1:
    sleep(0.5)

  all_rr = {}
  for p in plugins:
    for k, v in p.rr.iteritems():
      if k not in all_rr: all_rr[k] = []
      all_rr[k].extend(v)
    
  for k, v in all_rr.iteritems():
    getattr(BasePlugin, 'pprint_%s' % k)(v)


if __name__ == '__main__':
  main()

# vim: ts=2 sw=2 sts=2 et
