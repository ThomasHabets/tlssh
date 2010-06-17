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
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include<exception>
#include<string>

const char *port = "12345";
const char *certfile = "green.crap.retrofitta.se.crt";
const char *keyfile = "green.crap.retrofitta.se.key";

class FDWrap {
	int fd;
public:
	FDWrap(int fd = -1)
		:fd(fd)
	{
	}
	~FDWrap()
	{
		close();
	}
	void close()
	{
		if (fd > 0) {
			::close(fd);
			forget();
		}
	}

	int get() const
	{
		return fd;
	}

	int set(int n)
	{
		close();
		fd = n;
	}
	void forget()
	{
		fd = -1;
	}
};

class Socket {
	FDWrap fd;

	int create_socket()
	{
		int s;
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == -1) {
			throw ErrSys("socket");
		}
		fd.set(s);
	}
public:
	class ErrSys: public std::exception {
		std::string msg;
	public:
		ErrSys(const std::string &s)
			:msg(s)
		{
		}
		~ErrSys() throw() {}
	};

	int
	setsockopt_reuseaddr()
	{
		int on = 1;
		if (0 > setsockopt(fd.get(),
				   SOL_SOCKET,
				   SO_REUSEADDR,
				   &on,sizeof(on))) {
			throw ErrSys("reuse");
		}
	}
	int
	listen_any(int port)
	{
		create_socket();
		setsockopt_reuseaddr();

		int err;
		struct sockaddr_in sa;
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = INADDR_ANY;
		sa.sin_port = htons(port);
		err = bind(fd.get(), (struct sockaddr*)&sa, sizeof(sa));
		if (err) {
			throw ErrSys("bind()");
		}

		if (listen(fd.get(), 5)) {
			throw ErrSys("listen()");
		}
	}
	
};

class SSLSocket: public Socket {
};

void
server_loop(int fd)
{
	printf("Server loop %d\n", fd);

	SSL_CTX * ctx;

	ctx = SSL_CTX_new(TLSv1_server_method());
	
	printf("Loading cert...\n");
	if (1 != SSL_CTX_use_certificate_chain_file(ctx, certfile)) {
		perror("certchain");
	}
	printf("Loading key...\n");
	if (1 != SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)) {
		perror("keyfile");
	}
	//SSL_CTX_set_verify (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT

	printf("connecting SSL to socket...\n");
	SSL *ssl;
	if (!(ssl = SSL_new(ctx))) {
		perror("SSL_new()");
	}
	if (!SSL_set_fd(ssl, fd)) {
		perror("SSL_set_fd()");
	}
#if 1
	for (;;) {
		int err, sslerr;
		char buf[1024];

		printf("SSL_accept()...\n");
		err = SSL_accept(ssl);
		printf("\t%d\n", err);
		if (err == -1) {
			break;
		}

		printf("SSL_read()...\n");
		err = SSL_read(ssl, buf, sizeof(buf));
		printf("\t%d\n", err);
		if (err > 0) {
			buf[err] = 0;
			printf("%s\n", buf);
		}
		break;
	}
#else
	if (1 != SSL_do_handshake(ssl)) {
		perror("handshake");
		return;
	}
	
	// SSL_get_peer_certificate
	printf("Looping...\n");
	for(;;) {
		char buf[128];
		int err;

		err = SSL_read(ssl, buf, sizeof(buf));
		printf("data: %d\n");
		if (err <= 0) {
			break;
		}
	}
#endif
	printf("SSL_shutdown()...\n");
	SSL_shutdown(ssl);
}

void
listen_loop(int fd)
{
	printf("Listen\n");
	for(;;) {
		int client;
		struct sockaddr_storage sa;
		socklen_t salen = sizeof(sa); 
		if (0 > (client = accept(fd,
					 (struct sockaddr*)&sa,
					 &salen))) {
			continue;
		}
		if (0) {
			if (!fork()) {
				close(fd); /* close on fork? */
				server_loop(client);
				exit(0);
			}
		} else {
			server_loop(client);
		}
		close(client);
	}
}

int
main()
{
	SSL_library_init();
	SSL_load_error_strings();
	int fd;
	fd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(12345);

	int on = 1; 

	if (0 > setsockopt(fd,
			   SOL_SOCKET,
			   SO_REUSEADDR,
			   &on,sizeof(on))) {
		// Error logging code.
		perror("reuse");
	}

	if (bind(fd, (struct sockaddr*)&sa, sizeof(sa))) {
		perror("bind");
	}
	if (listen(fd, 5)) {
		perror("listen");
	}

	listen_loop(fd);
}
