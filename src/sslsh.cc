#ifdef HAVE_CONFIG_H
#include "config.h"
#endif



#include<iostream>

#include"sslsh.h"
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




BEGIN_NAMESPACE(sslsh);

struct Options {
	std::string port;
};
Options options = {
 port: "12345",
};
	
SSLSocket sock;

/**
 *
 */
int
new_connection()
{
	sock.ssl_connect();
	std::cout << sock.read() << std::endl;
}

END_NAMESPACE(ssl_shd);


BEGIN_LOCAL_NAMESPACE()
using namespace sslsh;
int
main2(int argc, char * const argv[])
{
	Socket rawsock;
	rawsock.connect("127.0.0.1", options.port);
	sock.ssl_attach(rawsock);
	return new_connection();
}
END_LOCAL_NAMESPACE()


int
main(int argc, char **argv)
{
	try {
		return main2(argc, argv);
	} catch (const std::exception &e) {
		std::cout << "std::exception: " << std::endl
                          << e.what() << std::endl;
	}

}