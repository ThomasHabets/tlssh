// tlssh/src/sslsocket.cc
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<iostream>
#include<sstream>
#include<vector>

#include<openssl/err.h>

#include"sslsocket.h"

#if 0
	char *randfile = "random.seed";
	int fd;
	RAND_load_file("/dev/urandom", 1024);

	unlink(randfile);
	fd = open(randfile, O_WRONLY | O_CREAT | O_EXCL, 0600);
	close(fd);
	RAND_write_file("random.seed");
#endif

/**
 *
 */
X509Wrap::X509Wrap(X509 *x509)
	:x509(x509)
{
	if (!x509) {
		throw "x509 init failed FIXME";
	}
}

/**
 *
 */
bool
X509Wrap::check_hostname(const std::string &host)
{
	int extcount;
	int i, j;

	// check X509v3 extensions
	extcount = X509_get_ext_count(x509);
	for (i = 0; i < extcount; i++) {
		X509_EXTENSION *ext;
		const char *extstr;

		ext = X509_get_ext(x509, i);
		extstr=OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
		if (!strcmp(extstr, "subjectAltName")) {
			X509V3_EXT_METHOD *meth;
			const unsigned char *data;
			STACK_OF(CONF_VALUE) *val;
			CONF_VALUE *nval;

			meth = X509V3_EXT_get(ext);
			if (!meth) {
				continue;
			}
			if (!meth->d2i) {
				printf("What?! meth->d2i missing?! FIXME\n");
				continue;
			}
			data = ext->value->data;
			val = meth->i2v(meth,
					meth->d2i(NULL,
						  &data,
						  ext->value->length),
					NULL);
			for (j = 0; j < sk_CONF_VALUE_num(val); j++) {
				nval = sk_CONF_VALUE_value(val, j);
				if (!strcmp(nval->name, "DNS")
				    && !strcmp(nval->value,
					       host.c_str())) {
					return true;
				}
			}
		}
	}

	// check subject name
	X509_NAME *subj;
	char sdata[256];
	subj = X509_get_subject_name(x509);
	if (!subj) {
		return false;
	}
	if (!X509_NAME_get_text_by_NID(subj, NID_commonName,
				       sdata, sizeof(sdata))) {
		return false;
	}
	sdata[sizeof(sdata) - 1] = 0;
	if (!strcmp(sdata, host.c_str())) {
		return true;
	}

	// default: name does not match
	return false;
}

/**
 *
 */
std::string
X509Wrap::get_common_name() const
{
	char buf[1024];
	X509_NAME *subj;

	subj = X509_get_subject_name(x509);
	if (!subj) {
		throw ErrSSL("X509_get_subject_name()");
	}
	if (!X509_NAME_get_text_by_NID(subj, NID_commonName,
				       buf, sizeof(buf))) {
		throw ErrSSL("X509_NAME_get_text_by_NID()");
	}
	buf[sizeof(buf) - 1] = 0;
	return std::string(buf);
}

/**
 *
 */
std::string
X509Wrap::get_issuer() const
{
	char buf[1024];
	X509_NAME_oneline(X509_get_issuer_name(x509),
			  buf, sizeof(buf));
	return std::string(buf);
}

/**
 *
 */
std::string
X509Wrap::get_subject() const
{
	char buf[1024];
	X509_NAME_oneline(X509_get_subject_name(x509),
			  buf, sizeof(buf));
	return std::string(buf);
}

/**
 *
 */
X509Wrap::~X509Wrap()
{
	if (x509) {
		X509_free(x509);
		x509 = 0;
	}
}

/**
 *
 */
X509Wrap::ErrSSL::ErrSSL(const std::string &s, SSL *ssl, int err)
	:ErrBase(s)
{
	if (ssl) {
		sslmsg = SSLSocket
			::ssl_errstr(
				     SSL_get_error(ssl, err));
	}
	msg = msg + ": " + sslmsg;
}

/**
 *
 */
SSLSocket::SSLSocket(int fd)
	:Socket(fd)
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_SSL_strings();
}

/**
 *
 */
std::auto_ptr<X509Wrap>
SSLSocket::get_cert()
{
	try {
                return std::auto_ptr<X509Wrap>
                        (new X509Wrap(SSL_get_peer_certificate(ssl)));
	} catch(...) {
		return std::auto_ptr<X509Wrap>(0);
	}
}

/**
 *
 */
const std::string
SSLSocket::ssl_errstr(int err)
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
		return "SSL_ERROR_SSL";
	}
	return "uhh.. what?";
}

/**
 *
 */
SSLSocket::~SSLSocket()
{
	shutdown();
}

/**
 *
 */
void
SSLSocket::release()
{
	fd.close();
}

/**
 *
 */
void
SSLSocket::shutdown()
{
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = 0;
	}
	ctx = 0;
}

/**
 *
 */
void
SSLSocket::ssl_attach(Socket &sock)
{
	fd.set(sock.getfd());
	sock.forget();
}

/**
 *
 */
void
SSLSocket::ssl_connect(const std::string &inhost)
{
	host = inhost;
	ssl_accept_connect(true);
}

/**
 *
 */
void
SSLSocket::ssl_accept()
{
	ssl_accept_connect(false);
}

DH*
SSLSocket::ssl_setup_dh()
{
        DH* dh = DH_new();
        if (!dh) {
                throw ErrSSL("DH_new()");
        }

        if (!DH_generate_parameters_ex(dh, 2, DH_GENERATOR_2, 0)) {
                throw ErrSSL("DH_generate_parameters_ex()");
        }

        int codes = 0;
        if (!DH_check(dh, &codes) && !codes) {
                throw ErrSSL("DH_check()");
        }

        if (!DH_generate_key(dh)) {
                throw ErrSSL("DH_generate_key()");
        }

        return dh;
}
/**
 *
 */
void
SSLSocket::ssl_accept_connect(bool isconnect)
{
	int err;

        // create CTX
        ctx = SSL_CTX_new(isconnect
                          ? TLSv1_client_method()
                          : TLSv1_server_method());
        if (!ctx) {
                throw ErrSSL("SSL_CTX_new");
	}

        // load cert & key
	if (1 != SSL_CTX_use_certificate_chain_file(ctx,
						    certfile.c_str())){
                throw ErrSSL("Load certfile " + certfile);
	}
	if (1 != SSL_CTX_use_PrivateKey_file(ctx,
					     keyfile.c_str(),
					     SSL_FILETYPE_PEM)) {
                throw ErrSSL("Load keyfile " + keyfile);
	}

        // set CAPath & CAFile for cert verification
	const char *ccapath = capath.c_str();
	const char *ccafile = cafile.c_str();
	if (!*ccafile) {
		ccafile = NULL;
	}
	if (!*ccapath) {
		ccapath = NULL;
	}
	if (ccafile || ccapath) {
		if (debug) {
			std::cout << "CAFile: " << ccafile << std::endl;
		}
		if (!SSL_CTX_load_verify_locations(ctx,
						   ccafile,
						   ccapath)) {
			throw ErrSSL("load_verify");
		}
		SSL_CTX_set_verify_depth(ctx, 5);
                SSL_CTX_set_verify(ctx,
                                   SSL_VERIFY_PEER
                                   | (isconnect
                                      ? 0
                                      : SSL_VERIFY_FAIL_IF_NO_PEER_CERT),
                                   NULL);
	}

        // set approved cipher list
	if (!cipher_list.empty()) {
		if (!SSL_CTX_set_cipher_list(ctx, cipher_list.c_str())) {
			throw ErrSSL("SSL_CTX_set_cipher_list");
                }
        }

        // if server, set up DH
        if (!isconnect) {
                if (!SSL_CTX_set_tmp_dh(ctx, ssl_setup_dh())) {
			throw ErrSSL("SSL_CTX_set_tmp_dh()");
                }
        }

        // create ssl object
	if (!(ssl = SSL_new(ctx))) {
		throw ErrSSL("SSL_new");
	}

        // attach fd to ssl object
	if (!SSL_set_fd(ssl, fd.get())) {
		throw ErrSSL("SSL_set_fd", ssl, err);
        }

        // do handshake
	if (isconnect) {
		err = SSL_connect(ssl);
		if (err == -1) {
			perror("SSL_connect fail");
			throw ErrSSL("SSL_connect", ssl, err);
		}
		if (SSL_get_verify_result(ssl) != X509_V_OK) {
			throw ErrSSL("SSL_get_verify_result() != X509_V_OK");
		}
		X509Wrap x(SSL_get_peer_certificate(ssl));
		if (!x.check_hostname(host)) {
			throw ErrSSLHostname(host, x.get_subject());
		}
	} else {
		err = SSL_accept(ssl);
		if (err == -1) {
			throw ErrSSL("SSL_accept()", ssl, err);
		}
	}

        // if debug, show cert info
	X509Wrap x(SSL_get_peer_certificate(ssl));
	if (debug) {
		std::cout << "  Issuer:  " << x.get_issuer() << std::endl
			  << "  Subject: " << x.get_subject() << std::endl
			  << "  Cipher: " << SSL_get_cipher_name(ssl)
                          << " (" <<SSL_get_cipher_bits(ssl, 0) << " bits)"
			  << std::endl
			  << "  Version: " << SSL_get_cipher_version(ssl)
			  << std::endl
			;
	}

}

/**
 *
 */
size_t
SSLSocket::write(const std::string &buf)
{
        int ret;
	ret = SSL_write(ssl, buf.data(), buf.length());
        if (ret <= 0) {
                throw ErrSSL("SSL_write()", ssl, SSL_get_error(ssl, ret));
        }
	return ret;
}

/**
 *
 */
std::string
SSLSocket::read(size_t m)
{
	int err, sslerr;
	std::vector<char> buf(m);
		
	err = SSL_read(ssl, &buf[0], m);
	if (err > 0) {
		return std::string(&buf[0], &buf[err]);
	}
	sslerr = SSL_get_error(ssl, err);
	if (err == 0 && sslerr == SSL_ERROR_ZERO_RETURN) {
		throw ErrPeerClosed();
	}
	throw ErrSSL("SSL_read", ssl, err);
}
	
/**
 *
 */
bool
SSLSocket::ssl_pending()
{
	return SSL_pending(ssl);
}

/**
 *
 */
void
SSLSocket::ssl_set_cipher_list(const std::string &lst)
{
	cipher_list = lst;
}

/**
 *
 */
void
SSLSocket::ssl_set_capath(const std::string &s)
{
	capath = s;
}

/**
 *
 */
void
SSLSocket::ssl_set_cafile(const std::string &s)
{
	cafile = s;
}

/**
 *
 */
void
SSLSocket::ssl_set_certfile(const std::string &s)
{
	certfile = s;
}

/**
 *
 */
void
SSLSocket::ssl_set_keyfile(const std::string &s)
{
	keyfile = s;
}

/**
 *
 */
SSLSocket::ErrSSL::ErrSSL(const std::string &s, SSL *ssl, int err)
			:ErrBase(s)
{
	if (ssl) {
		sslmsg = SSLSocket::ssl_errstr(SSL_get_error(ssl, err));
	}
	msg = msg + ": " + sslmsg;

	for (;;) {
		unsigned long err;
		const char *file;
		int line;
		const char *data;
		int flags;
		err = ERR_get_error_line_data(&file,
					      &line,
					      &data,
					      &flags);
		if (!err) {
			break;
		}
		SSLSocket::ErrQueueEntry e;
		e.file = file;
		e.line = line;
		e.data = data;
		e.flags = flags;
		char buf[1024];
		ERR_error_string_n(err, buf, sizeof(buf));
		e.str = buf;
		errqueue.push_back(e);
	}
}

/**
 *
 */
std::string
SSLSocket::ErrSSL::human_readable() const
{
	errqueue_t::const_iterator itr;
	std::stringstream ret;
	int c = 0;

	ret << "------- SSL Error -------" << std::endl
	    << "Exception message: " << what() << std::endl;

	for (itr = errqueue.begin();
	     itr != errqueue.end();
	     ++itr) {
		ret << "SSL Error number " << ++c << ":" << std::endl
		    << "  " << itr->str << std::endl
		    << "  File:  " << itr->file << std::endl
		    << "  Line:  " << itr->line << std::endl
		    << "  Data:  " << itr->data << std::endl
		    << "  Flags: " << itr->flags << std::endl
			;
	}
	return ret.str();
}

/**
 *
 */
SSLSocket::ErrSSLHostname::ErrSSLHostname(const std::string &host,
					  const std::string &subject)
	:ErrSSL("")
{
	msg = "Cert " + subject + " does not match hostname " + host;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
