heartleech
==========

A typical "heartbleed" tool. What makes this different is:

  - autopwn (`-a`) that does all the steps needed to get private key
  - post-handshake (encrypted) heartbeats instead of during handshake
  - evades Snort IDS rules
  - loops making repeated requests (`-l <loopcount>`)
  - dumps binary data to file (`-f <filename>`)
  - IPv4 or IPv6 (`-v <IPver>`)
  - full 64k heartbleeds
  

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

    gcc ../heartleech/heartleech.c libcrypto.a libssl.a -ldl -o heartleech

On Cygwin (and maybe other platforms), the order in which you link the
libraries apparently matters, so do "`libcrypto.a`" first, then "`libssl.a`", 
then "`-ldl`".

On Windows with VisualStudio, this is the guide I use for building:
    
    http://developer.covenanteyes.com/building-openssl-for-visual-studio/

The VisualStudio 2010 project looks for a 32-bit version in "..\openssl32"
and a 64-bit version in "..\openssl64" (in other words, the "openssl" directory
is at the same level as the "heartleech" directory). Apparently, configuring
OpenSSL for one 32/64 bits leaves artifacts behind that disrupt the other
build, so you need two separate directories to build the two different sizes.

Mac OS X includes OpenSSL/0.9.8, which doesn't support heartbeats. Therefore,
you need to follow the same steps as above. However, instead of the normal
"`./config`" command, you have to do "`./Configure darwin64-x86_64-cc`". I 
just build the 64-bit version, but in theory you should be able to build
the 32-bit version and even the PowerPC version. If you want to make a
"universal" binary containing all the versions, you'll have to build each
static library separately, then link them all together.


#Running#

Run like the following:

    ./heartleech www.cloudflarechallenge.com -f challenge.bin
  
This will send a million heartbeat requests to the server, which by the way 
will create a 64-gigabyte file, since each heartbeat is 64KB in size. You can
then grep that file for cookies, keys, and so on.

Or, run like the following

    ./heartleech www.cloudflarechallenge.com -a
    
This will automatically search the contents looking for prime factors for RSA
keys, and if found, rebuilds the private key file for you and exits. Doesn't
work with non-RSA keys.

You can also search existing files gathered by other tools, or even other
memory dumps that have nothing to do with the heartbleed bug, but which may
have private keys.

    ./heartleech -c challenge.pem -F scan.binaries


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
coding it.
