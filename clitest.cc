#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include<string>

#include"sslsocket.h"

int
main()
{
	int err;
	SSL_load_error_strings();
	SSL_library_init();

	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	printf("ctx\n");
	printf("load\n");
	/*
	if(!SSL_CTX_load_verify_locations(ctx,
					  "class3.crt",
					  NULL)) {
		perror("load_verify");
		return 1;
	}
	*/


	printf("socket()...\n");
	int sd;
	struct sockaddr_in sa;
	if (0 > (sd = socket (AF_INET, SOCK_STREAM, 0))) {
		perror("socket()");
		return 1;
	}
 
	memset (&sa, '\0', sizeof(sa));
	sa.sin_family      = AF_INET;
	sa.sin_addr.s_addr = inet_addr ("127.0.0.1");   /* Server IP */
	sa.sin_port        = htons     (12345);     /* Server Port number */
  
	
	printf("connect()...\n");
	if (0 > connect(sd,
			(struct sockaddr*) &sa,
			sizeof(sa))) {
		perror("connect()");
		return 1;
	}

	printf("SSL magic()...\n");
	SSLSocket sock(sd);
	sock.ssl_connect();
	const char *buf = "GET / HTTP/1.0\r\nHost: blog.habets.pp.se\r\n\r\n";
	sock.write(buf);
}

