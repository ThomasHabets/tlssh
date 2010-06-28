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
const char *argv0 = NULL;

const std::string DEFAULT_PORT         = "12345";
const std::string DEFAULT_CERTFILE     = "~/.tlssh/keys/default.crt";
const std::string DEFAULT_KEYFILE      = "~/.tlssh/keys/default.key";
const std::string DEFAULT_SERVERCAFILE = "/etc/tlssh/ServerCA.crt";
const std::string DEFAULT_SERVERCAPATH = "";
const std::string DEFAULT_CONFIG       = "/etc/tlssh/tlssh.conf";
const std::string DEFAULT_CIPHER_LIST  = "HIGH";


struct Options {
	std::string port;
	std::string certfile;
	std::string keyfile;
	std::string servercafile;
	std::string servercapath;
	std::string config;
	std::string cipher_list;
	unsigned int verbose;
};
Options options = {
 port:         DEFAULT_PORT,
 certfile:     DEFAULT_CERTFILE,
 keyfile:      DEFAULT_KEYFILE,
 servercafile: DEFAULT_SERVERCAFILE,
 servercapath: DEFAULT_SERVERCAPATH,
 config:       DEFAULT_CONFIG,
 cipher_list:  DEFAULT_CIPHER_LIST,
 verbose:      0,
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
bool old_tio_set = false;
void
reset_tio(void)
{
	if (old_tio_set) {
		tcsetattr(0, TCSADRAIN, &old_tio);
	}
}

/**
 *
 */
int
new_connection()
{
	sock.ssl_connect();

	FDWrap terminal(0);

	tcgetattr(terminal.get(), &old_tio);
	old_tio_set = true;
	atexit(reset_tio);

	struct termios tio;
	cfmakeraw(&tio);
	tcsetattr(terminal.get(), TCSADRAIN, &tio);

	mainloop(terminal);
	terminal.forget();
}

std::string
xwordexp(const std::string &in)
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
usage(int err)
{
	printf("%s [ -hv ] "
	       "[ -c <config> ] "
	       "[ -C <cipher-list> ] "
	       "[ -p <cert+keyfile> ]"
	       "\n"
	       "\t-c <config>          Config file (default %s)\n"
	       "\t-C <cipher-list>     Acceptable ciphers (default %s)\n"
	       "\t-h, --help           Help\n"
	       "\t-V, --version        Print version and exit\n"
	       "\t-p <cert+keyfile>    Load login cert+kef from file\n"
	       , argv0,
	       DEFAULT_CONFIG.c_str(), DEFAULT_CIPHER_LIST.c_str());
	exit(err);
}

void
print_version()
{
	printf("tlssh version", VERSION);
}

/**
 * FIXME: implement this
 */
void
read_config_file(const std::string &fn)
{
}

/**
 *
 */
void
parse_options(int argc, char * const *argv)
{
	int c;

	// expand default options
	options.certfile = xwordexp(options.certfile);
	options.keyfile = xwordexp(options.keyfile);

	// special options
	for (c = 1; c < argc - 1; c++) {
		if (!strcmp(argv[c], "--")) {
			break;
		} else if (!strcmp(argv[c], "--help")) {
			usage(0);
		} else if (!strcmp(argv[c], "--version")) {
			print_version();
			exit(0);
		} else if (!strcmp(argv[c], "-c")) {
			read_config_file(argv[c+1]);
		}
	}

	int opt;
	while ((opt = getopt(argc, argv, "c:C:hp:vV")) != -1) {
		switch (opt) {
		case 'c':  // already handled above
			break;
		case 'C':
			options.cipher_list = optarg;
			break;
		case 'h':
			usage(0);
			break;
		case 'p':
			options.certfile = optarg;
			options.keyfile = optarg;
			break;
		case 'v':
			options.verbose++;
			break;
		case 'V':
			print_version();
			exit(0);
			break;
		default:
			usage(1);
		}
	}
}


END_NAMESPACE(tlssh);


BEGIN_LOCAL_NAMESPACE()
using namespace tlssh;
int
main2(int argc, char * const argv[])
{
	parse_options(argc, argv);
	sock.ssl_set_cipher_list(options.cipher_list);
	sock.ssl_set_capath(options.servercapath);
	sock.ssl_set_cafile(options.servercafile);
	sock.ssl_set_certfile(options.certfile);
	sock.ssl_set_keyfile(options.keyfile);
	if (options.verbose) {
		sock.set_debug(true);
	}

	Socket rawsock;

	rawsock.connect("127.0.0.1", options.port);
	sock.ssl_attach(rawsock);
	return new_connection();
}
END_LOCAL_NAMESPACE()


int
main(int argc, char **argv)
{
	argv0 = argv[0];
	try {
		try {
			return main2(argc, argv);
		} catch(...) {
			reset_tio();
			throw;
		}
	} catch(const SSLSocket::ErrSSL &e) {
		reset_tio();
		std::cerr << e.human_readable();
	} catch (const std::exception &e) {
		std::cout << "tlssh::main() std::exception: "
			  << e.what() << std::endl;
	} catch (const char *e) {
		std::cerr << "FIXME: " << std::endl
			  << e << std::endl;
	}
}
