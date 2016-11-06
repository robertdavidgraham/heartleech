all: openssl heartleech

openssl:
	if [ ! -d openssl ] ; then git clone git://git.openssl.org/openssl.git && cd openssl && git checkout bb3e20cf8c5e733c16fe68ce41f67eea5a2a520e && ./config && make && make depend ; fi

heartleech: heartleech.c
	gcc heartleech.c -Iopenssl -Iopenssl/include -Iopenssl/crypto/include -Iopenssl/ssl openssl/libssl.a openssl/libcrypto.a -ldl -lpthread -o heartleech

clean:
	-rm -r heartleech openssl
