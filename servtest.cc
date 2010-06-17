#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include<exception>
#include<string>
#include<iostream>

#include "sslsocket.h"

const int port = 12345;
const char *certfile = "green.crap.retrofitta.se.crt";
const char *keyfile = "green.crap.retrofitta.se.key";

void
server_loop(SSLSocket &sock)
{
	printf("Server loop\n");

	for (;;) {
		try {
			std::cout << sock.read() << std::endl;
		} catch (const Socket::ErrPeerClosed &e) {
			printf("EOF, it seems\n");
			break;
		}
	}
}

void
handle_connection(FDWrap &fd)
{
	try {
		SSLSocket sock(fd.get());
		fd.forget();
		sock.ssl_accept(certfile, keyfile);
		server_loop(sock);
	} catch (const std::exception &e) {
		std::cerr << "std::exception: " << std::endl
			  << e.what() << std::endl;
	} catch (...) {
		std::cerr << "Unknown exception happened\n";
	}
}

void
listen_loop(Socket &sock)
{
	printf("Listen\n");
	for(;;) {
		FDWrap clifd;
		struct sockaddr_storage sa;
		socklen_t salen = sizeof(sa); 
		clifd.set(accept(sock.getfd(),
				 (struct sockaddr*)&sa,
				 &salen));
		if (0 > clifd.get()) {
			continue;
		}
		if (!fork()) {
			handle_connection(clifd);
			exit(0);
		} else {
			clifd.close();
		}
	}
}

int
main()
{
	try {
		Socket sock;
		sock.listen_any(port);
		listen_loop(sock);
	} catch (const std::exception &e) {
		std::cout << "std::exception: " << std::endl
			  << e.what() << std::endl;
	}
}
