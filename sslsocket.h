/* -*- c++ -*- */
#include<openssl/bio.h>
#include<openssl/x509v3.h>
#include<openssl/ssl.h>
#include<openssl/rand.h>
#include<string>
#include<exception>

#include"socket.h"

class SSLSocket: public Socket {
	SSL_CTX *ctx;
	SSL *ssl;

	SSLSocket &operator=(const SSLSocket&);
	SSLSocket(const SSLSocket&);
public:
	class ErrSSL: public Socket::ErrBase {
		std::string sslmsg;
	public:
		ErrSSL(const std::string &s, SSL *ssl = 0, int err = 0)
			:ErrBase(s)
		{
			if (ssl) {
				sslmsg = SSLSocket
					::ssl_errstr(
						     SSL_get_error(ssl, err));
			}
			msg = msg + ": " + sslmsg;
		}
		~ErrSSL() throw() {};
	};

	static const std::string ssl_errstr(int err);

	SSLSocket(int fd);
	~SSLSocket();

	void release();

	void shutdown();
	void ssl_accept(const std::string &certfile,
			const std::string &keyfile);
	void ssl_connect();
	std::string read();
	void write(const std::string &);
};
