

heartleech: heartleech.c ../openssl-1.0.1f/ssl/t1_lib.c
    gcc -I ../openssl-1.0.1f/include -L ../openssl-1.0.1f/out32 -lssleay32 -leay32 -o heartleech heartleech.c


