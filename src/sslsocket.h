/* -*- c++ -*- */
// tlssh/src/sslsocket.h
#include<openssl/bio.h>
#include<openssl/x509v3.h>
#include<openssl/ssl.h>
#include<openssl/rand.h>
#include<string>
#include<list>
#include<exception>
#include<memory>

#include"socket.h"

/**
 *
 */
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

/**
 *
 */
class SSLSocket: public Socket {
	SSL_CTX *ctx;
	SSL *ssl;
	std::string cipher_list;
	std::string certfile;
	std::string keyfile;
	std::string capath;
	std::string cafile;
	std::string host;

	void ssl_accept_connect(bool);
	SSLSocket &operator=(const SSLSocket&);
	SSLSocket(const SSLSocket&);
public:
	struct ErrQueueEntry {
		std::string file;
		int line;
		std::string data;
		int flags;
		std::string str;
	};
	class ErrSSL: public Socket::ErrBase {
		std::string sslmsg;
	public:
		typedef std::list<struct ErrQueueEntry> errqueue_t;
		errqueue_t errqueue;
		std::string human_readable() const;
		ErrSSL(const std::string &s, SSL *ssl = 0, int err = 0);
		~ErrSSL() throw() {};
	};
	class ErrSSLHostname: public ErrSSL {
	public:
		ErrSSLHostname(const std::string &host,
			       const std::string &subject);
	};

	static const std::string ssl_errstr(int err);

	SSLSocket(int fd = -1);
	~SSLSocket();

	void ssl_attach(Socket&sock);

	bool ssl_pending();
	void ssl_set_cipher_list(const std::string &lst);
	void ssl_set_capath(const std::string &s);
	void ssl_set_cafile(const std::string &s);
	void ssl_set_certfile(const std::string &s);
	void ssl_set_keyfile(const std::string &s);

	std::auto_ptr<X509Wrap> get_cert();

	void release();

	void shutdown();
	void ssl_accept();
	void ssl_connect(const std::string &s);
	virtual std::string read(size_t m = 4096);
	virtual size_t write(const std::string &);
};

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
