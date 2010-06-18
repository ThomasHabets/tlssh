#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<iostream>

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
		continue;

		ext = X509_get_ext(x509, i);
		extstr = OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
		if (!strcmp(extstr, "subjectAltName")) {
			X509V3_EXT_METHOD *meth;
			const unsigned char *data;
			STACK_OF(CONF_VALUE) *val;
			CONF_VALUE *nval;

			printf("alt1!\n");

			meth = X509V3_EXT_get(ext);
			if (!meth) {
				break; // FIXME: why?
			}
			printf("alt2!\n");
			data = ext->value->data;
			printf("alt3 %p!\n", ext->value->data);
			printf("fa %p\n", 
			       meth->d2i(NULL,
					 &data,
					 ext->value->length));
			printf("alt4\n");
			val = meth->i2v(meth,
					meth->d2i(NULL,
						  &data,
						  ext->value->length),
					NULL);
			printf("alt4!\n");
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
	if (!X509_NAME_get_text_by_NID(subj, NID_commonName, sdata,
				       sizeof(sdata))) {
		return false;
	}
	sdata[sizeof(sdata) - 1] = 0;
	if (!strcmp(sdata, host.c_str())) {
		return true;
	}
	return false;
}

std::string
X509Wrap::get_issuer()
{
	char buf[1024];
	X509_NAME_oneline(X509_get_issuer_name(x509),
			  buf, sizeof(buf));
	return std::string(buf);
}

std::string
X509Wrap::get_subject()
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

SSLSocket::SSLSocket(int fd)
	:Socket(fd)
{
	SSL_library_init();
	SSL_load_error_strings();
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
		return "ssl";
	}
	return "uhh.. what?";
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
	printf("SSL_shutdown()...\n");
	if (ssl) {
		SSL_shutdown(ssl);
		ssl = 0;
	}
	ctx = 0;
	printf("SSL_shutdown() done\n");
}

void
SSLSocket::ssl_attach(Socket &sock)
{
	fd.set(sock.getfd());
	sock.forget();
}

void
SSLSocket::ssl_connect()
{
	ctx = SSL_CTX_new(TLSv1_client_method());
        if (!(ssl = SSL_new(ctx))) {
		throw ErrSSL("SSL_new");
	}

	if(!SSL_CTX_load_verify_locations(ctx,
                                          "class3.crt",
                                          NULL)) {
                throw ErrSSL("load_verify");
        }

	SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
	SSL_set_verify_depth(ssl, 5);
	/* FIXME, make verify work */
	SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

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
		      const std::string &keyfile)
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
	//SSL_CTX_set_verify (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT

	if (!(ssl = SSL_new(ctx))) {
		perror("SSL_new()");
	}
	printf("connecting SSL to socket...\n");
	if (!SSL_set_fd(ssl, fd.get())) {
		perror("SSL_set_fd()");
	}
	printf("SSL_accept()...\n");
	err = SSL_accept(ssl);
	printf("\t%d\n", err);
	if (err == -1) {
		throw ErrSSL("SSL_accept()", ssl, err);
	}

	X509 *x;
        x = SSL_get_peer_certificate(ssl);
	if (!x){
		// FIXME
		//throw ErrSSL("SSL_get_peer_certificate", ssl);
        } else {
		X509_free(x);
	}
}

void
SSLSocket::write(const std::string &buf)
{
	const char *p;
	p = buf.data();
	SSL_write(ssl, p, buf.length());
}

std::string
SSLSocket::read()
{
	char buf[1024];
	int err, sslerr;
		
	printf("SSL_read()...\n");
	err = SSL_read(ssl, buf, sizeof(buf));
	printf("\t%d\n", err);
	if (err > 0) {
		return std::string(buf, buf+err);
	}
	sslerr = SSL_get_error(ssl, err);
	if (err == 0 && sslerr == SSL_ERROR_ZERO_RETURN) {
		throw ErrPeerClosed();
	}
	throw ErrSSL("SSL_read", ssl, err);
}
	
