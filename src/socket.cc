// tlssh/src/socket.cc
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<netinet/in.h>
#include<netinet/tcp.h>
#include<sys/types.h>
#include<sys/socket.h>

#include"socket.h"
#include"gaiwrap.h"


/**
 *
 */
Socket::Socket(int infd)
	:debug(false)
{
	fd.set(infd);
}

/**
 *
 */
void
Socket::create_socket(const struct addrinfo *ai)
{
	int s;
	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (s == -1) {
		throw ErrSys("socket");
	}
	fd.set(s);
}

/**
 *
 */
int
Socket::getfd() const
{
	return fd.get();
}

/**
 *
 */
void
Socket::forget()
{
	fd.forget();
}

/**
 *
 */
void
Socket::set_reuseaddr(bool ion)
{
	int on = !!ion;
	if (0 > setsockopt(fd.get(),
			   SOL_SOCKET,
			   SO_REUSEADDR,
			   &on,sizeof(on))) {
		throw ErrSys("reuse");
	}
}

/**
 *
 */
void
Socket::connect(int af, const std::string &host, const std::string &port)
{
	struct addrinfo hints;
	struct addrinfo *p;
	int err;


	memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_family = af;
        hints.ai_socktype = SOCK_STREAM;

	GetAddrInfo gai(host, port, &hints);
	p = gai.fixme();
	if (!fd.valid()) {
		create_socket(p);
	}
	err = ::connect(fd.get(), p->ai_addr, p->ai_addrlen);
	if (0 > err) {
		throw ErrSys("connect");
	}
        set_tcp_md5_sock();
}

/**
 *
 */
void
Socket::listen_any(int af, const std::string &port)
{

	int err;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;
        hints.ai_family = af;
        hints.ai_socktype = SOCK_STREAM;

	GetAddrInfo gai("", port, &hints);
	struct addrinfo *p;
	p = gai.fixme();

	create_socket(p);
	set_reuseaddr(true);

	err = bind(fd.get(), p->ai_addr, p->ai_addrlen);
	if (err) {
		throw ErrSys("bind()");
	}

	if (listen(fd.get(), 5)) {
		throw ErrSys("listen()");
	}
}

/**
 *
 */
void
Socket::close()
{
        fd.close();
}

/**
 *
 */
Socket::~Socket()
{
        close();
}

/**
 *
 */
std::string
Socket::read(size_t m)
{
	return fd.read(m);
}

/**
 *
 */
size_t
Socket::write(const std::string &data)
{
	return fd.write(data);
}

/**
 *
 */
void
Socket::full_write(const std::string &data)
{
        fd.full_write(data);
}

/**
 *
 */
void
Socket::set_nodelay(bool on)
{
        int parm = !!on;
        if (-1 == setsockopt(fd.get(), IPPROTO_TCP, TCP_NODELAY, &parm,
                             sizeof(parm))) {
		throw ErrSys("setsockopt(TCP_NODELAY)");
        }
}

/**
 *
 */
void
Socket::set_keepalive(bool on)
{
        int parm = !!on;
        if (-1 == setsockopt(fd.get(), SOL_SOCKET, SO_KEEPALIVE, &parm,
                             sizeof(parm))) {
		throw ErrSys("setsockopt(SO_KEEPALIVE)");
        }
}

/**
 *
 */
void
Socket::set_tcp_md5(const std::string &keystring)
{
        tcpmd5 = keystring;
}

/**
 *
 */
void
Socket::set_tcp_md5_sock()
{
        return; // FIXME: enable later. I think this makes Linux crash
        struct tcp_md5sig md5sig;
        std::string key = tcpmd5.substr(0, TCP_MD5SIG_MAXKEYLEN);
        socklen_t t = sizeof(struct sockaddr_storage);

        memset(&md5sig, 0, sizeof(md5sig));
        if (getpeername(fd.get(),
                        (struct sockaddr*)&md5sig.tcpm_addr, &t)) {
                throw ErrSys("getpeername()");
        }
        md5sig.tcpm_keylen = key.size();
        memcpy(md5sig.tcpm_key, key.data(), md5sig.tcpm_keylen);
        if (-1 == setsockopt(fd.get(),
                             IPPROTO_TCP, TCP_MD5SIG,
                             &md5sig, sizeof(md5sig))) {
                if (ENOENT == errno) {
                        // when we set no key
                } else {
                        throw ErrSys("setsockopt(TCP_MD5SIG)");
                }
        }
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
