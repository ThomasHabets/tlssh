#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>

#include"socket.h"
#include"gaiwrap.h"


Socket::Socket(int infd)
	:debug(false)
{
	fd.set(infd);
}

int
Socket::create_socket()
{
	int s;
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == -1) {
		throw ErrSys("socket");
	}
	fd.set(s);
}


int
Socket::getfd() const
{
	return fd.get();
}

void
Socket::forget()
{
	fd.forget();
}

int
Socket::setsockopt_reuseaddr()
{
	int on = 1;
	if (0 > setsockopt(fd.get(),
			   SOL_SOCKET,
			   SO_REUSEADDR,
			   &on,sizeof(on))) {
		throw ErrSys("reuse");
	}
}

void
Socket::connect(const std::string &host, const std::string &port)
{
	struct addrinfo hints;
	struct addrinfo *p;
	int err;


	memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_ADDRCONFIG;
        hints.ai_socktype = SOCK_STREAM;

	GetAddrInfo gai(host, port, &hints);
	p = gai.fixme();
	if (!fd.valid()) {
		create_socket();
	}
	err = ::connect(fd.get(), p->ai_addr, p->ai_addrlen);
	if (0 > err) {
		throw ErrSys("connect");
	}
}

int
Socket::listen_any(int port)
{
	create_socket();
	setsockopt_reuseaddr();

	int err;
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(port);
	err = bind(fd.get(), (struct sockaddr*)&sa, sizeof(sa));
	if (err) {
		throw ErrSys("bind()");
	}

	if (listen(fd.get(), 5)) {
		throw ErrSys("listen()");
	}
}
	

Socket::~Socket()
{
}

std::string
Socket::read(size_t m)
{
	return fd.read(m);
}

size_t
Socket::write(const std::string &data)
{
	return fd.write(data);
}
