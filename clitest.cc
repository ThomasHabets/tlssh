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
const std::string
SSL_errstr(int err)
{
	switch (err) {
	case SSL_ERROR_NONE:
		return "None";
	case SSL_ERROR_ZERO_RETURN:
		return "zero return";
	case SSL_ERROR_WANT_READ:
		return "want read";
	case SSL_ERROR_WANT_WRITE:
		return "want write";
	case SSL_ERROR_WANT_CONNECT:
		return "want connect";
	case SSL_ERROR_WANT_ACCEPT:
		return "want accept";
	case SSL_ERROR_WANT_X509_LOOKUP:
		return "x509 lookup";
	case SSL_ERROR_SYSCALL:
		return "syscall";
	case SSL_ERROR_SSL:
		return "ssl";
 	}
	return "uhh.. what?";
}

int
main()
{
	int err;
	SSL_load_error_strings();
	SSL_library_init();

	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	printf("ctx\n");
	SSL_CTX * ctx = SSL_CTX_new(TLSv1_client_method());
	printf("load\n");
	if(!SSL_CTX_load_verify_locations(ctx,
					  "class3.crt",
					  NULL)) {
		perror("load_verify");
		return 1;
	}
	printf("new\n");
	SSL * ssl;
	if (!(ssl = SSL_new(ctx))) {
		perror("SSL_new()");
		return 1;
	}


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

	printf("SSL_set_fd()...\n");
	if (!SSL_set_fd(ssl, sd)) {
		perror("SSL_set_fd()");
		return 1;
	}

	printf("SSL_connect()...\n");
	err = SSL_connect(ssl);
	if (err == -1) {
		err = SSL_get_error(ssl, err);
		printf("SSL_connect() %d %s\n",
		       err,
		       SSL_errstr(err).c_str());
		return 1;
	}

	printf("SSL_write()...\n");
	char *buf = "GET / HTTP/1.0\r\nHost: blog.habets.pp.se\r\n\r\n";
	SSL_write(ssl, buf, strlen(buf));
	SSL_shutdown(ssl);
	printf("done\n");

	//BIO_free_all(bio);
}

