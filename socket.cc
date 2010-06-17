#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<string.h>

#include"socket.h"
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

Socket::Socket(int infd)
{
	fd.set(infd);
}

int Socket::getfd() const { return fd.get(); }

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
	
