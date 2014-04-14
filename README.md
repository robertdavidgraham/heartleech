heartleech
==========

A typical "heartbleed" tool. What makes this different is:

  - autopwn most (`-a`) that does all the steps neeeded to get private key
  - post-handshake (encrypted) heartbeats instead of during handshake
  - evades Snort IDS rules
  - loops making repeated requests (`-l <loopcount>`)
  - dumps binary data to file (`-f <filename>`)
  - IPv4 or IPv6 (`-v <IPver>`)
  - full 64k heartbleeds
  

#Building#

This is tricky. This uses the `ssl3_write_bytes()` function in order to send
heartbeats encrypted after the SSL handshake is complete. This function is
sometimes exported in OpenSSL libraries, and sometimes not.

If that's the trouble, then you have to download and build OpenSSL, then
link this tool with their object files. I did this by doing:

    git clone git://git.openssl.org/openssl.git
    cd openssl
    ./config
    make depend
    make

    gcc ../heartleech/heartleech.c *.a -ldl -lssl -o heartleech
  
This is evil, because I'm simultaneously linking to the local libraries
and the system libraries for OpenSSL, but it seems to work without
too much trouble.


#Running#

Run like the following:

    ./heartleech www.cloudflarechallenge.com -f challenge.bin
  
This will send a million heartbeat requests to the server, which by the way will
create a 64-gigabyte file, since each heartbeet is 64k in size. You can then
grep that file for cookies, keys, and so on.

Or, run like the following

    ./heartleech www.cloudflarechallenge.com -a
    
This will automatically search the contents looking for prime factors for RSA
keys, and if found, rebuilds the private key file for you and exits. Doesn't
work with non-RSA keys.


#Discussion#

This should be a useful tool on its own, but I wrote it primarily because the
pattern-matching rules for Snort are inadequate. IDS vendors won't fix their
stuff until I can prove they are inadequate.

The problem with the signatures is that they trigger on the heartbeat pattern
as the start of the TCP payload, looking for a pattern like this:

    18 03 02 00 03 01 40 00

However, TCP is a not a "packet" protocol but a "streaming" protocol. While
this bytes may be typically at the start of the TCP payload, they don't have
to be.

Therefore, I created this tool such that these bytes don't appear at the
start of a packet's payload. Instead, they appear in the middle.

The IDSs look for these patterns both coming from the attacker and also
coming from the server. Therefore, I have to manipulate both sides of the 
connection in roder to cause the evasion.

I do this on the client side by sending an HTTP GET request back-to-back with
a heartbeat requests. This was the most difficult part of the program. Normally,
with an SSL API, you let the underlying library take care of network/sockets
communications for you. However, that creates two separate TCP packets on the
wire when I want just one packet with two SSL records. Therefore, I had to
use my own sockets communiations, then use the OpenSSL "memory BIO" feature
to encrypt/decrypt data separately. There's not a log of documentation on how
to do this, so it took a while to get it to work.

On the server side, the replies natureally come back together. I havne't tested
anywhere by the CloudFlare challenge server, but I think this should almost
always be the case. My looks for |18 03| as the packet header and warns you
when this isn't the case.


#IDS References#

Here are some IDS links to the signatures in question

    http://vrt-blog.snort.org/2014/04/performing-heartbleed-attack-after-tls.html?utm_source=twitterfeed&utm_medium=twitter


#Other scripts#

Other people have different programs that do similar things to this:

      https://raw.githubusercontent.com/HackerFantastic/Public/master/exploits/heartbleed.c
