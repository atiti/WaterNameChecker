#!/usr/bin/env python

# Steps to check the domain:
# 
# 1. Try to resolve
# 2. Try to whois
# 3. Look up on google
# 4. Look up on twitter
# 5. Look up on facebook

TLDS = [".com", ".dk"]


import time, os, string, sys, traceback
import socket, urllib, json, random
import whois

fd = open("out.csv", "w")
proxy = []

def write_entry(n, domain):
	global fd
	line = n+", "
	keys = ["resolve", "whois", "google"]
	for k in keys:
		if not domain.has_key(k):
			return
		for vk in domain[k].keys():
			line += str(domain[k][vk])+", "

	fd.write(line+"\n")
	fd.flush()

def load_names(f):
	fd = open(f, "r")
	buff = fd.read().split("\n")
	fd.close()
	return buff

# load proxies
# http://powerfulproxy.com/latest.txt
def load_proxies():
	global proxy
	p = load_names("latest.txt")
	for l in p:
		if len(l) < 1:
			continue
		v = l.split(",")
		if v[2] == "HTTP":
			proxy.append(v[0]+":"+v[1])
	return proxy

def random_proxy():
	global proxy
	return proxy[random.randint(0,len(proxy))]

def get_page_With_proxy(url, proxy):
        user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
	headers = { 'User-Agent': user_agent }
	try:
		proxy = urllib2.ProxyHandler({'http': proxy})
		opener = urllib2.build_opener(proxy)
		urllib2.install_opener(opener)
		req = urllib2.Request(url, None, headers)
		r = urllib2.urlopen(req)
		data = r.read()
		return data
	except:
		print "Failed to load page."
	return None

# Fast way of determining if the domain is in use.
# If it does not resolve, it might still be registered.
def do_resolve(n, domain):
	global TLDS
	resolv = {}
	for t in TLDS:
		try:
			ip = socket.gethostbyname(n+t)
			resolv[t] = 1
		except:
#			traceback.print_exc()
			try:
				ip = socket.gethostbyname("www."+n+t)
				resolv[t] = 1
			except:
				resolv[t] = 0	
#				traceback.print_exc()

	if len(resolv.keys()):
		domain["resolve"] = resolv
	return domain

def do_whois(n, domain):
	whoiss = {}
	tlds = domain["resolve"].keys()
	for t in tlds:
		if domain["resolve"][t] == 1:
			whoiss[t] = 1
			continue

		try:
			w = whois.query(n+t)
			whoiss[t] = 1
		except:
			whoiss[t] = 0
			traceback.print_exc()
	if len(whoiss.keys()):
		domain["whois"] = whoiss
	
	return domain

def do_google(n, domain):
	query = urllib.urlencode({'q': n})
	url = 'http://ajax.googleapis.com/ajax/services/search/web?v=1.0&%s' % query
	
	randomproxy = random_proxy()
	print "Using proxy "+randomproxy
	search_response = get_page_with_proxy(url, randomproxy)
	#search_response = urllib.urlopen(url)
	search_results = search_response.read()
	results = json.loads(search_results)
	if results["responseStatus"] == 200: 
		data = results['responseData']
		if not data:
			return domain
		domain["google"] = {"resultcount" : data['cursor']['estimatedResultCount']} #, 'results':data['results'], 'moreresults':data['cursor']['moreResultsUrl']}
	else:
		print "We got throttled by google!"
		time.sleep(5)
		domain = do_google(n, domain)

	return domain

def check_keys(domain, n):
	found = 0
	for v in domain[n].keys():
		if domain[n][v] == 1:
			return 1
	return 0

def do_check(n):
	domain = {}
	domain = do_resolve(n, domain)
	if domain.has_key("resolve"):
		if check_keys(domain, "resolve"):
			print "Domain resolves! Dropping..."
			return {}

		domain = do_whois(n, domain)
		if check_keys(domain, "whois"):
			print "Domain is owned! Dropping..."
			return {}
		domain = do_google(n, domain)

	print repr(domain)
	return domain

def check_names(a):
	numnames = len(a)
	cnt = 0
	for n in a:
		print str(cnt)+"/"+str(numnames)+" Trying",n
		domain = do_check(n)
		write_entry(n, domain)
		cnt += 1



if len(sys.argv) < 2:
	print "Usage: ./check.py [file]"
	sys.exit(0)

names = load_names(sys.argv[1])

check_names(names[0:100])
