#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<poll.h>
#include<termios.h>
#include<unistd.h>
#include<wordexp.h>

#include<iostream>

#include"tlssh.h"
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




BEGIN_NAMESPACE(tlssh);

// Constants

const std::string DEFAULT_PORT         = "12345";
const std::string DEFAULT_CERTFILE     = "~/.tlssh/keys/default.crt";
const std::string DEFAULT_KEYFILE      = "~/.tlssh/keys/default.key";
const std::string DEFAULT_SERVERCAFILE = "/etc/tlssh/ServerCA.crt";
const std::string DEFAULT_SERVERCAPATH = "";
const std::string DEFAULT_CONFIG       = "/etc/tlssh/tlssh.conf";


struct Options {
	std::string port;
	std::string certfile;
	std::string keyfile;
	std::string servercafile;
	std::string servercapath;
	std::string config;
};
Options options = {
 port:         DEFAULT_PORT,
 certfile:     DEFAULT_CERTFILE,
 keyfile:      DEFAULT_KEYFILE,
 servercafile: DEFAULT_SERVERCAFILE,
 servercapath: DEFAULT_SERVERCAPATH,
 config:       DEFAULT_CONFIG,
};
	
SSLSocket sock;

void
mainloop(FDWrap &terminal)
{
	struct pollfd fds[2];
	int err;
	std::string to_server;
	std::string to_terminal;
	for (;;) {
		fds[0].fd = sock.getfd();
		fds[0].events = POLLIN;
		if (!to_server.empty()) {
			fds[0].events |= POLLOUT;
		}

		fds[1].fd = terminal.get();
		fds[1].events = POLLIN;
		if (!to_terminal.empty()) {
			fds[1].events |= POLLOUT;
		}

		err = poll(fds, 2, -1);
		if (!err) { // timeout
			continue;
		}
		if (0 > err) { // error
			continue;
		}

		// from client
		if (fds[0].revents & POLLIN) {
			try {
				do {
					to_terminal += sock.read();
				} while (sock.ssl_pending());
			} catch(const Socket::ErrPeerClosed &e) {
				return;
			}
		}

		// from terminal
		if (fds[1].revents & POLLIN) {
			to_server += terminal.read();
		}

		if ((fds[0].revents & POLLOUT)
		    && !to_server.empty()) {
			size_t n;
			n = sock.write(to_server);
			to_server = to_server.substr(n);
		}

		if ((fds[1].revents & POLLOUT)
		    && !to_terminal.empty()) {
			size_t n;
			n = terminal.write(to_terminal);
			to_terminal = to_terminal.substr(n);
		}
	}
}


struct termios old_tio;
void
reset_tio(void)
{
	tcsetattr(0, TCSADRAIN, &old_tio);
}

/**
 *
 */
int
new_connection()
{
	sock.ssl_connect(options.certfile,
			 options.keyfile,
			 options.servercafile,
			 options.servercapath);

	FDWrap terminal(0);

	tcgetattr(terminal.get(), &old_tio);
	atexit(reset_tio);

	struct termios tio;
	cfmakeraw(&tio);
	tcsetattr(terminal.get(), TCSADRAIN, &tio);

	mainloop(terminal);
	terminal.forget();
}

std::string
wordexp_option(const std::string &in)
{
	wordexp_t p;
	char **w;
	int i;

	if (wordexp(in.c_str(), &p, 0)) {
		throw "FIXME: wordexp()";
	}

	if (p.we_wordc != 1) {
		throw "FIXME: wordexp() nmatch != 1";
	}

	std::string ret(p.we_wordv[0]);
	wordfree(&p);
	return ret;
}

void
wordexp_options()
{
	options.certfile = wordexp_option(options.certfile);
	options.keyfile = wordexp_option(options.keyfile);
}

END_NAMESPACE(tlssh);


BEGIN_LOCAL_NAMESPACE()
using namespace tlssh;
int
main2(int argc, char * const argv[])
{
	Socket rawsock;

	wordexp_options();

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
		std::cout << "tlssh::main() std::exception: "
			  << e.what() << std::endl;
	} catch (const char *e) {
		std::cerr << "FIXME: " << std::endl
			  << e << std::endl;
	}

}
