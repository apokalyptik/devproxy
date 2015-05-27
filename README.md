# devproxy
A Socks5 proxy server meant for development and testing purposes

When you're developing a large site, or set of sites, using a 
single sandbox you will come across cases where unit testing 
with something like http://casperjs.org/ is fairly difficult
due to the number of host names which need to be accessed to
test the full funcitonality of your site(s).  What you really
want is to be able to specify a number of hostnames that you
want connected to your sandbox IP address instead of their
public DNS addresses so that your unit tests are run against
local code instead of deployed code.  Running the following
command will give you a socks5 proxy server listening on
127.0.0.1:8888 (no authentication) through which you can 
connect to anything as normal except that any request to 
one.com will be made to the server at two.com and any request 
to a.com will be made to the server at b.com

``` bash
devproxy \
	-listen=127.0.0.1:8888 \
	-rewrite=one.com:two.com,a.com:b.com
```

That's the long and short of it.

I used https://github.com/christopherhesse/go-socks-proxy-example
as a starting point for developing this proxy. Very little of that
code or functionality remains.

Changelog:

* bug fix: handle properly when clients offer more than one
		authentication type. Previously those would overrun into
		the request itself and push out other parameters...
* bug fix: handle resolving and using ipv6 addresses for CONNECT
		bug fix: properly send responses to clients. Tested working
		with phantomjs and --proxy-type=socks5. Tested working with
		curl and -socks5-hostname. Tested working with chrome (osx)
		and switchy (http://switchy.samabox.com/)
