/* -*- c++ -*- */
#include<openssl/bio.h>
#include<openssl/x509v3.h>
#include<openssl/ssl.h>
#include<openssl/rand.h>
#include<string>
#include<exception>
#include<memory>

#include"socket.h"

class X509Wrap {
	X509 *x509;
	X509Wrap(const X509Wrap&);
	X509Wrap operator=(const X509Wrap&);
public:
	X509Wrap(X509 *x509);

	bool check_hostname(const std::string &host);

	std::string get_issuer();

	std::string get_subject();

	~X509Wrap();
};



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

	SSLSocket(int fd = -1);
	~SSLSocket();

	void ssl_attach(Socket&sock);

	std::auto_ptr<X509Wrap> get_cert();

	void release();

	void shutdown();
	void ssl_accept(const std::string &certfile,
			const std::string &keyfile);
	void ssl_connect();
	std::string read();
	void write(const std::string &);
};
