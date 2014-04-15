heartleech(8) -- Exploits OpenSSL heartbleed vulnerability
=======================================

## SYNOPSIS

heartleech <host> [-p<port>] [-f<filename>] [-a]
heartleech -F<filename> -c<certficate> 

## DESCRIPTION

**heartleech** exploits the well-known "heartbleed" bug in OpenSSL-1.0.1f.
It has a number of features that improve over other heartbleed exploits,
such as automatically extracting the SSL private-key (autopwn).

## OPTIONS

  * `<host>`: the target's name, IPv4 address, or IPv6 address.

  * `-p <port>`: the port number to connect to on the target machine. If not
    specified, the port number 443 will be used.

  * `-f <filename>`: the file where bleeding information is stored. Typically,
    the user will use this program to grab data from a server, then use
    other tools to search those files for things, such as cookies, passwords,
    and private strings.

  * `-a`: sets "auto-pwn" mode, which automatically searches the bleeding
    buffers for the private-key. If the private-key is found, it will be
    printed to <stdout>, and the program will exit.

  * `-F`: instead of running live against a server, this option causes
    the program to run forensics on existing files, looking for private
    keys. The option `-c` must also be used.

  * `-c`: in offline mode, this option tells the program the certificate to
    load. A certificate, containing the public-key, is needed in order to 
    search data for the matching components of a private key. In online
    mode, this option isn't necessary, because the certificate is fetched
    from the server duing the SSL handshake.

  * `-d`: sets the 'debug' flag, which causes a lot of debug information to
    be printed to <stderr>. Using this will help diagnose connection problems.

  * `-v <ipver>`: sets the version of IP to use, either 4 for IPv4 or 6 for 
    IPv6. Otherwise, the program tries to guess from the address given,
    or chooses whichever is first when doing a DNS lookup.

  * `-S`: randomizes the size of heartbleed requests. Normally, the program
    requests for the max 64k size, but with this setting, each request
    will have a random size between 200 and 64k. Some believe that heartbeats
    of different size will produce different results.

  * `-l <count>`: the number of times to loop and try a heartbeat again. The
    default count is 1000000 (one-million). A count of 1 grabs just a single
    heartbeat.

## SIMPLE EXAMPLES

The following is the easiest way to use the program, to grab the private-key
form the server in 'auto-pwn' mode:

    $ heartleech www.example.com -a

This auto-pwn mode will search for the heartbeat payloads looking for the 
components of the private-key that matches the server's certificate (which
it automatically retrieves). When a certificate is found, it's printed to
<stdout>. The user can then copy it to a file and use it for anythign that
private-keys can be used for.

Heartbleed information contains more than just private keys. On a typical
web-server, it'll contain session cookies (useful for sidejacking) and
passwords. In that case, the way to use this program is to save all the
heartbleed information into a file. Note that these files quickly grow
to gigabytes in size:

    $ heartleech www.example.com -f bleed.bin
    <ctrl-c>
    $ grep -iobUaP "Cookie:.*\n" bleed.bin

## IDS EVASION

Soon after the Heartbleed vulnerability was announced, many people published 
'rules' for Snort-like intrusion-detection engines. These rules all trigger
on the pattern |18 03| in the first two bytes of the TCP payloads.

By default, this program avoids putting that pattern in the first two bytes.
Instead, it tries to put those bytes elsewhere in the payload. Thus, this
program should genrally avoid that sort of detection.

Note that this isn't complete IDS evasion. The open-source Bro program,
and many commercial products, do a full SSL protocol decode, and therefore
catch this exploit no matter where it is in the packet. Also, by the time
you read this, it's probable that the Snort-like engines will have upgraded
their code to support SSL decodes as well.


## SEE ALSO

masscan(8)

## AUTHORS

This tool was written by Robert Graham. The source code is available at
https://github.com/robertdavidgraham/heartbleed
