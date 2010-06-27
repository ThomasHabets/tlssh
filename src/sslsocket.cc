#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<iostream>

#include<openssl/err.h>

#include"sslsocket.h"

X509Wrap::X509Wrap(X509 *x509)
	:x509(x509)
{
	if (!x509) {
		throw "x509 init failed FIXME";
	}
}

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

		// FIXME: this code segfaults!
		//continue;

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
				printf("What?! meth->d2i missing?!\n");
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
		throw ErrSSL("X509_get_subject_name()");
	}
	buf[sizeof(buf) - 1] = 0;
	return std::string(buf);
}

std::string
X509Wrap::get_issuer() const
{
	char buf[1024];
	X509_NAME_oneline(X509_get_issuer_name(x509),
			  buf, sizeof(buf));
	return std::string(buf);
}

std::string
X509Wrap::get_subject() const
{
	char buf[1024];
	X509_NAME_oneline(X509_get_subject_name(x509),
			  buf, sizeof(buf));
	return std::string(buf);
}

X509Wrap::~X509Wrap()
{
	if (x509) {
		X509_free(x509);
		x509 = 0;
	}
}

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

SSLSocket::SSLSocket(int fd)
	:Socket(fd)
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_SSL_strings();
}

std::auto_ptr<X509Wrap>
SSLSocket::get_cert()
{
	try {
		return std::auto_ptr<X509Wrap>(new X509Wrap(SSL_get_peer_certificate(ssl)));
	} catch(...) {
		return std::auto_ptr<X509Wrap>(0);
	}
}

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

static void
ssl_print_err_queue()
{
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
		printf("\tSSL error: %s:%d: (%d) <%s>\n",
		       file, line, flags, data);
		char buf[1024];
		ERR_error_string_n(err, buf, sizeof(buf));
		printf("\tStr: %s\n", buf);
	}
}

SSLSocket::~SSLSocket()
{
	shutdown();
}

void
SSLSocket::release()
{
	fd.close();
}

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

void
SSLSocket::ssl_attach(Socket &sock)
{
	fd.set(sock.getfd());
	sock.forget();
}

void
SSLSocket::ssl_connect(const std::string &certfile,
		       const std::string &keyfile,
		       const std::string &cafile,
		       const std::string &capath)
{
	ctx = SSL_CTX_new(TLSv1_client_method());

	if (!certfile.empty()) {
		printf("Loading cert %s %s...\n",
		       certfile.c_str(),
		       keyfile.c_str());
		if (1 != SSL_CTX_use_certificate_chain_file(ctx,
							    certfile.c_str())){
			perror("certchain");
		}
		if (1 != SSL_CTX_use_PrivateKey_file(ctx,
						     keyfile.c_str(),
						     SSL_FILETYPE_PEM)) {
			perror("keyfile");
		}
	}

	const char *ccapath = capath.c_str();
	const char *ccafile = cafile.c_str();
	if (!*ccafile) {
		ccafile = NULL;
	}
	if (!*ccapath) {
		ccapath = NULL;
	}
	if (ccafile || ccapath) {
		printf("Loading CA verification stuff...\n");
		if (!SSL_CTX_load_verify_locations(ctx,
						   ccafile,
						   ccapath)) {
			throw ErrSSL("load_verify");
		}
		SSL_CTX_set_verify_depth(ctx, 5);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		/* FIXME, make verify work */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	}
        if (!(ssl = SSL_new(ctx))) {
		throw ErrSSL("SSL_new");
	}

	int err;
	if (!SSL_set_fd(ssl, fd.get())) {
		throw ErrSSL("SSL_set_fd", ssl, err);
	}
	err = SSL_connect(ssl);
	if (err == -1) {
		perror("ffoo");
		throw ErrSSL("SSL_connect", ssl, err);
	}
        printf("verify mode & depth: %d %d\n",
	       SSL_CTX_get_verify_mode(ctx),
	       SSL_CTX_get_verify_depth(ctx));
	printf("verified: %d (should be %d)\n",
	       SSL_get_verify_result(ssl), X509_V_OK);

	X509Wrap x(SSL_get_peer_certificate(ssl));
	std::cout << "  Issuer:  " << x.get_issuer() << std::endl
		  << "  Subject: " << x.get_subject() << std::endl;
	if (!x.check_hostname("green.crap.retrofitta.se")) {
		throw ErrSSL("cert does not match hostname");
	}
}
void
SSLSocket::ssl_accept(const std::string &certfile,
		      const std::string &keyfile,
		      const std::string &cafile,
		      const std::string &capath)
{
	int err;
	ctx = SSL_CTX_new(TLSv1_server_method());

	if (1 != SSL_CTX_use_certificate_chain_file(ctx,
						    certfile.c_str())){
		perror("certchain");
	}
	if (1 != SSL_CTX_use_PrivateKey_file(ctx,
					     keyfile.c_str(),
					     SSL_FILETYPE_PEM)) {
		perror("keyfile");
	}

	const char *ccapath = capath.c_str();
	const char *ccafile = cafile.c_str();
	if (!*ccafile) {
		ccafile = NULL;
	}
	if (!*ccapath) {
		ccapath = NULL;
	}
	if (ccafile || ccapath) {
		printf("Loading CA verification stuff...\n");
		if (!SSL_CTX_load_verify_locations(ctx,
						   ccafile,
						   ccapath)) {
			throw ErrSSL("load_verify");
		}
		SSL_CTX_set_verify_depth(ctx, 5);
		SSL_CTX_set_verify(ctx,
				   SSL_VERIFY_PEER
				   | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
				   NULL);
	}

	if (!(ssl = SSL_new(ctx))) {
		perror("SSL_new()");
	}
	printf("connecting SSL to socket...\n");
	if (!SSL_set_fd(ssl, fd.get())) {
		perror("SSL_set_fd()");
	}
	printf("SSL_accept()...\n");
	err = SSL_accept(ssl);
	printf("\tAccept status: %d\n", err);
	if (err == -1) {
		ssl_print_err_queue();
		throw ErrSSL("SSL_accept()", ssl, err);
	}

	X509Wrap x(SSL_get_peer_certificate(ssl));
	std::cout << "  Issuer:  " << x.get_issuer() << std::endl
		  << "  Subject: " << x.get_subject() << std::endl;
}

size_t
SSLSocket::write(const std::string &buf)
{
	size_t ret;
	ret = SSL_write(ssl, buf.data(), buf.length());
	return ret;
}

std::string
SSLSocket::read()
{
	char buf[1024];
	int err, sslerr;
		
	err = SSL_read(ssl, buf, sizeof(buf));
	if (err > 0) {
		return std::string(buf, buf+err);
	}
	sslerr = SSL_get_error(ssl, err);
	if (err == 0 && sslerr == SSL_ERROR_ZERO_RETURN) {
		throw ErrPeerClosed();
	}
	throw ErrSSL("SSL_read", ssl, err);
}
	
bool
SSLSocket::ssl_pending()
{
	return SSL_pending(ssl);
}
