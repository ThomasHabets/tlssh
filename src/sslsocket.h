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
	class ErrBase: public std::exception {
	protected:
		std::string msg;
	public:
		ErrBase(const std::string &s):msg(s){}
		~ErrBase() throw() {}
		const char *what() const throw() { return msg.c_str(); }
	};
	class ErrSSL: public ErrBase {
		std::string sslmsg;
	public:
		ErrSSL(const std::string &s, SSL *ssl = 0, int err = 0);
		~ErrSSL() throw() {};
	};
	X509Wrap(X509 *x509);

	bool check_hostname(const std::string &host);

	std::string get_issuer() const;
	std::string get_common_name() const;
	std::string get_subject() const;

	~X509Wrap();
};

class SSLSocket: public Socket {
	SSL_CTX *ctx;
	SSL *ssl;
	std::string cipher_list;

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

	bool ssl_pending();
	void ssl_set_cipher_list(const std::string &lst);

	std::auto_ptr<X509Wrap> get_cert();

	void release();

	void shutdown();
	void ssl_accept(const std::string &certfile,
			const std::string &keyfile,
			const std::string &cafile = "",
			const std::string &capath = "");
	void ssl_connect(const std::string &certfile = "",
			 const std::string &keyfile = "",
			 const std::string &cafile = "",
			 const std::string &capath = "");
	virtual std::string read();
	virtual size_t write(const std::string &);
};
