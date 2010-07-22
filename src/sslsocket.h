/* -*- c++ -*- */
/**
 * @file src/sslsocket.h
 * SSLSocket class
 */
#include<string>
#include<list>
#include<exception>
#include<memory>

#include<openssl/bio.h>
#include<openssl/x509v3.h>
#include<openssl/ssl.h>
#include<openssl/rand.h>

#include"socket.h"
#include"errbase.h"

/**
 * OpenSSL X509 structure wrapper.
 */
class X509Wrap {
	X509 *x509;
	X509Wrap(const X509Wrap&);
	X509Wrap operator=(const X509Wrap&);
public:
        /**
         * Base exception class
         */
	class ErrBase: public Err::ErrBase {
	public:
		ErrBase(const Err::ErrData &errdata,
                        const std::string &m
                        ):Err::ErrBase(errdata, m){}
		virtual ~ErrBase() throw() {}
	};

        /**
         * SSL Errors
         *
         * @todo Should be merged with ErrSSL tree somehow
         */
	class ErrSSL: public ErrBase {
		std::string sslmsg;
	public:
		ErrSSL(const Err::ErrData &errdata,
                       const std::string &m,
                       SSL *ssl = 0, int err = 0);
		virtual ~ErrSSL() throw() {};
	};
	X509Wrap(X509 *x509);

	bool check_hostname(const std::string &host);

	std::string get_issuer() const;
	std::string get_common_name() const;
	std::string get_subject() const;

        static const std::string errstr(int err);

        X509 *get() { return x509; }

	~X509Wrap();
};

/**
 * SSL Socket
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
	std::string crlfile;

	SSLSocket &operator=(const SSLSocket&);
	SSLSocket(const SSLSocket&);

	void ssl_accept_connect(bool);
        void check_crl();
        void check_ocsp();
        DH *ssl_setup_dh();
public:
        /**
         * Error Queue entry from OpenSSL
         */
	struct ErrQueueEntry {
		std::string file;
		int line;
		std::string data;
		int flags;
		std::string str;
	};

        /**
         * SSL library exception
         */
	class ErrSSL: public Socket::ErrBase {
		std::string sslmsg;
	public:
		typedef std::list<struct ErrQueueEntry> errqueue_t;
		errqueue_t errqueue;
		std::string what_verbose() const throw();
		ErrSSL(const Err::ErrData &errdata, const std::string &m,
                       SSL *ssl = 0, int err = 0);
		virtual ~ErrSSL() throw() {};
	};

        /**
         * CRL check failed
         */
	class ErrSSLCRL: public ErrSSL {
                const std::string subject;
	public:
		ErrSSLCRL(const Err::ErrData &errdata,
                          const std::string &subject);
		virtual ~ErrSSLCRL() throw() {};
	};

        /**
         * Exception hostname doesn't match subject name
         */
	class ErrSSLHostname: public ErrSSL {
	public:
		ErrSSLHostname(const Err::ErrData &errdata,
                               const std::string &host,
			       const std::string &subject);
	};

	static const std::string ssl_errstr(int err);

	SSLSocket(int fd = -1);
	virtual ~SSLSocket();

	void ssl_attach(Socket&sock);

	bool ssl_pending();
	void ssl_set_cipher_list(const std::string &lst);
	void ssl_set_capath(const std::string &s);
	void ssl_set_cafile(const std::string &s);
	void ssl_set_certfile(const std::string &s);
	void ssl_set_keyfile(const std::string &s);
	void ssl_set_crlfile(const std::string &s);

	std::auto_ptr<X509Wrap> get_cert();

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
