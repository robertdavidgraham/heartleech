

heartleech: heartleech.c
	gcc -I../openssl/include -L../openssl -lcrypto -lssl -lcrypto -ldl -lpthread -o heartleech heartleech.c


