#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include"sslsocket.h"

SSLSocket::SSLSocket(int fd)
	:Socket(fd)
{
	SSL_library_init();
	SSL_load_error_strings();
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

	X509 *x;
	char buf[1024];
	x = SSL_get_peer_certificate(ssl);
	if (!x) {
		throw ErrSSL("SSL_get_peer_certificate", ssl);
	}
	if (1) {
		X509_NAME_oneline(X509_get_issuer_name(x), buf, sizeof(buf));
		printf("  issuer name: %s\n", buf);
		X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
		printf("  subject name: %s\n", buf);
	}
	X509_free(x);
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
	
