#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <pwd.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

#include<memory>
#include<iostream>

#include"sslsh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"


/**
 * FIXME; make reentrant
 */
std::auto_ptr<struct passwd>
xgetpwnam(const std::string &name)
{
	char pwbuf[1024];
	struct passwd pw;
	struct passwd *npw;
	struct passwd *ppw = 0;
	if (xgetpwnam_r(name.c_str(), &pw, pwbuf, sizeof(pwbuf), &ppw)
	    || !ppw) {
		throw "FIXME";
	}
	npw = new struct passwd;
	memcpy(npw, &pw, sizeof(pw));

	return std::auto_ptr<struct passwd>(npw);
}

BEGIN_NAMESPACE(sslshd);

struct Options {
	std::string port;
	std::string certfile;
	std::string keyfile;
};
Options options = {
 port: "12345",
 certfile: "green.crap.retrofitta.se.crt",
 keyfile: "green.crap.retrofitta.se.key",
};
	
Socket listen;

/**
 * verify cert information
 */
void
new_ssl_connection(SSLSocket &sock)
{
	std::auto_ptr<X509Wrap> cert = sock.get_cert();
	if (!cert.get()) {
		std::cerr << "Client provided no cert.\n";
		sock.write("No cert provided.");
		return;
	}

	std::string username = "thompa";
	std::auto_ptr<struct passwd> pw = xgetpwnam(username);
	std::cout << pw->pw_name << std::endl
		  << pw->pw_shell << std::endl;
	sock.write(pw->pw_shell);
}

/**
 * input: newly connected fd, and newly forked process
 * output: calls new_ssl_connection() with up-and-running SSL connection
 */
void
new_connection(FDWrap&fd)
{
	try {
		SSLSocket sock(fd.get());
		fd.forget();
		sock.ssl_accept(options.certfile,
				options.keyfile);
		new_ssl_connection(sock);
	} catch (const std::exception &e) {
		std::cerr << "std::exception: " << std::endl
			  << e.what() << std::endl;
	} catch (const char *e) {
		std::cerr << "FIXME: " << std::endl
			  << e << std::endl;
	} catch (...) {
		std::cerr << "Unknown exception happened\n";
		throw;
	}
}

int
listen_loop()
{
	for (;;) {
		FDWrap clifd;
		struct sockaddr_storage sa;
		socklen_t salen = sizeof(sa); 
		clifd.set(::accept(listen.getfd(),
				 (struct sockaddr*)&sa,
				 &salen));
		if (0 > clifd.get()) {
			continue;
		}
		if (!fork()) {
			new_connection(clifd);
			exit(0);
		} else {
			clifd.close();
		}
	}
}

END_NAMESPACE(sslshd);

BEGIN_LOCAL_NAMESPACE()
using namespace sslshd;
int
main2(int argc, char * const argv[])
{
	sslshd::listen.listen_any(atoi(options.port.c_str()));
	return listen_loop();
}
END_LOCAL_NAMESPACE()

int
main(int argc, char **argv)
{
	try {
		return main2(argc, argv);
	} catch (const std::exception &e) {
		std::cout << "std::exception: " << std::endl
			  << "\t" << e.what() << std::endl;
	}
}
