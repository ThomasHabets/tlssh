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

        // set up CRL check.
        // DISABLED: while this works, it gives the error message
        // SSL_accept()[...]no certificate returned.
        // so check is made after connection is made, at the end of this
        // function
        if (0 && !crlfile.empty()) {
                // http://bugs.unrealircd.org/view.php?id=2043
                X509_STORE *store = SSL_CTX_get_cert_store(ctx);
                X509_LOOKUP *lookup=X509_STORE_add_lookup(store,
                                                          X509_LOOKUP_file());

                if (!X509_load_crl_file(lookup,
                                       crlfile.c_str(),
                                       X509_FILETYPE_PEM)) {
                        throw ErrSSL("X509_load_crl_file");
                }

                if (!X509_STORE_set_flags(store,
                                         X509_V_FLAG_CRL_CHECK
                                         | X509_V_FLAG_CRL_CHECK_ALL
                                         )) {
                        throw ErrSSL("X509_STORE_set_flags");
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

        check_crl();
        if (isconnect) {
                check_ocsp();
        }
}

/**
 * http://etutorials.org/Programming/secure+programming/Chapter+10.+Public+Key+Infrastructure/10.12+Checking+Revocation+Status+via+OCSP+with+OpenSSL/
 */
#define FINALLY(a,b) try { a } catch(...) { b; throw; }
void
SSLSocket::check_ocsp()
{
#if 0
        const char *url = "http://ocsp.cacert.org/";
        char *host = 0;
        char *port = 0;
        SSL_CTX               *ctx2 = 0;
        X509_STORE            *store = 0;
        OCSP_CERTID           *id;
        OCSP_REQUEST          *req = 0;
        OCSP_RESPONSE         *resp = 0;
        OCSP_BASICRESP        *basic = 0;
        ASN1_GENERALIZEDTIME  *producedAt, *thisUpdate, *nextUpdate;

        FINALLY(
#if 0
        // indent right in emacs
                );
#endif

        if (!OCSP_parse_url(url, &host, &port, &path, &ssl)) {
                throw ErrSSL("OCSP_parse_url");
        }

        if (!(req = OCSP_REQUEST_new(  ))) {
                throw ErrSSL("OCSP_REQUEST_new");
        }

        id = OCSP_cert_to_id(0, data->cert, data->issuer);
        if (!id || !OCSP_request_add0_id(req, id)) {
                throw ErrSSL("OCSP_request_add0_id");
        }

        OCSP_request_add1_nonce(req, 0, -1);
        /* sign the request */
#if 0
        if (data->sign_cert && data->sign_key &&
            !OCSP_request_sign(req, data->sign_cert, data->sign_key, EVP_sha1(  ), 0, 0)) {
                throw ErrSSL("OCSP_request_sign");
        }
#endif
        /* establish a connection to the OCSP responder */
        if (!(bio = spc_connect(host, atoi(port), ssl, data->store, &ctx))) {
                throw ErrSSL("OSCP connect");
        }

        /* send the request and get a response */
        resp = OCSP_sendreq_bio(bio, path, req);
        if ((rc = OCSP_response_status(resp)) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
                throw ErrSSL("OCSP_response_status");
        }

        /* verify the response */
        if (!(basic = OCSP_response_get1_basic(resp))) {
                        throw ErrSSL("OCSP_response_get1_basic");
        }
        if (OCSP_check_nonce(req, basic) <= 0) {
                throw ErrSSL("OCSP_check_nonce");
        }
        if (data->store && !(store = spc_create_x509store(data->store))) {
                throw ErrSSL("spc_create_x509store");
        }
        if ((rc = OCSP_basic_verify(basic, 0, store, 0)) <= 0) {
                throw ErrSSL("OCSP_basic_verify");
        }
        if (!OCSP_resp_find_status(basic, id, &status, &reason, &producedAt,
                                   &thisUpdate, &nextUpdate)) {
                throw ErrSSL("OCSP_resp_find_status");
        }
        if (!OCSP_check_validity(thisUpdate,
                                 nextUpdate, data->skew, data->maxage)) {
                throw ErrSSL("OCSP_check_validity");
        }
        /* All done.  Set the return code based on the status from the
           response. */
        if (status =  = V_OCSP_CERTSTATUS_REVOKED) {
                result = SPC_OCSPRESULT_CERTIFICATE_REVOKED;
        } else {
                result = SPC_OCSPRESULT_CERTIFICATE_VALID;
        }

        ,    /*  FINALLY */;

        if (bio) BIO_free_all(bio);
        if (host) OPENSSL_free(host);
        if (port) OPENSSL_free(port);
        if (path) OPENSSL_free(path);
        if (req) OCSP_REQUEST_free(req);
        if (resp) OCSP_RESPONSE_free(resp);
        if (basic) OCSP_BASICRESP_free(basic);
        if (ctx) SSL_CTX_free(ctx);
        if (store) X509_STORE_free(store);
#if 0
        // indent right in emacs
        (
#endif
        );
#endif
}

/**
 * check CRL.
 * FIXME: CRL only works if cafile is used, not capath
 * http://etutorials.org/Programming/secure+programming/Chapter+10.+Public+Key+Infrastructure/10.5+Performing+X.509+Certificate+Verification+with+OpenSSL/
 */
void
SSLSocket::check_crl()
{
        int err;

        if (crlfile.empty()) {
                return;
        }

	X509Wrap cert(SSL_get_peer_certificate(ssl));
        X509_STORE_CTX *ctx2 = X509_STORE_CTX_new();
        X509_STORE *store = X509_STORE_new();
        X509_LOOKUP *lookup = X509_STORE_add_lookup(store,
                                                    X509_LOOKUP_file());

        if (!X509_load_cert_file(lookup,
                                 cafile.c_str(),
                                 X509_FILETYPE_PEM)) {
                throw ErrSSL("X509_load_cert_file");
        }

        if (!X509_load_crl_file(lookup,
                                crlfile.c_str(),
                                X509_FILETYPE_PEM)) {
                if (!X509_load_crl_file(lookup,
                                        crlfile.c_str(),
                                        X509_FILETYPE_ASN1)) {
                        throw ErrSSL("X509_load_crl_file");
                }
        }

        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
                             X509_V_FLAG_CRL_CHECK_ALL);

        X509_STORE_CTX_init(ctx2, store, cert.get(), 0);
        if (1 != (err = X509_verify_cert(ctx2))) {
                throw ErrSSL("CRL check failed");
        }
        X509_STORE_CTX_free(ctx2);
        X509_STORE_free(store); // need this?
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
SSLSocket::ssl_set_crlfile(const std::string &s)
{
	crlfile = s;
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
