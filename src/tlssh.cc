#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<poll.h>
#include<termios.h>
#include<unistd.h>
#include<wordexp.h>
#include<signal.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include<iostream>
#include<fstream>

#include"tlssh.h"
#include"util.h"
#include"sslsocket.h"
#include"configparser.h"

using namespace tlssh_common;

BEGIN_NAMESPACE(tlssh);

// Constants
const char *argv0 = NULL;
const std::string protocol_version     = "tlssh.1";

const std::string DEFAULT_PORT         = "12345";
const std::string DEFAULT_CERTFILE     = "~/.tlssh/keys/default.crt";
const std::string DEFAULT_KEYFILE      = "~/.tlssh/keys/default.key";
const std::string DEFAULT_SERVERCAFILE = "/etc/tlssh/ServerCA.crt";
const std::string DEFAULT_SERVERCAPATH = "";
const std::string DEFAULT_CONFIG       = "/etc/tlssh/tlssh.conf";
const std::string DEFAULT_CIPHER_LIST  = "HIGH";
const std::string DEFAULT_TCP_MD5      = "tlssh";


struct Options {
	std::string port;
	std::string certfile;
	std::string keyfile;
	std::string servercafile;
	std::string servercapath;
	std::string config;
	std::string cipher_list;
	std::string host;
	std::string tcp_md5;
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
 host:         "",
 tcp_md5:      DEFAULT_TCP_MD5,
 verbose:      0,
};
	
SSLSocket sock;

bool sigwinch_received = true;
void
sigwinch(int)
{
        sigwinch_received = true;
}

std::pair<int,int>
terminal_size()
{
        struct winsize ws;
        if (ioctl(fileno(stdin), TIOCGWINSZ, (char *)&ws)) {
                throw "FIXME: ioctl(TIOCGWINSZ)";
        }
        return std::pair<int,int>(ws.ws_row, ws.ws_col);
}

std::string
iac_window_size()
{
        std::pair<int,int> ts(terminal_size());

        IACCommand cmd;
        cmd.s.iac = 255;
        cmd.s.command = 1;
        cmd.s.commands.ws.rows = htons(ts.first);
        cmd.s.commands.ws.cols = htons(ts.second);
        return std::string(&cmd.buf[0], &cmd.buf[6]);
}

std::string
terminal_type()
{
        // FIXME: only letters and numbers
        return getenv("TERM");
}

void
mainloop(FDWrap &terminal)
{
	struct pollfd fds[2];
	int err;
	std::string to_server;
	std::string to_terminal;

	for (;;) {
                if (sigwinch_received) {
                        sigwinch_received = false;
                        to_server += iac_window_size();
                }

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
	sock.ssl_connect(options.host);
        sock.write("version " + protocol_version + "\n");
        sock.write("env TERM " + terminal_type() + "\n");
        sock.write("\n");

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
	       "\t-p <cert+keyfile>    Load login cert+key from file\n"
	       , argv0,
	       DEFAULT_CONFIG.c_str(), DEFAULT_CIPHER_LIST.c_str());
	exit(err);
}

void
print_version()
{
	printf("tlssh %s\n"
	       "Copyright (C) 2010 Thomas Habets <thomas@habets.pp.se>\n"
	       "License GPLv2: GNU GPL version 2 or later "
	       "<http://gnu.org/licenses/gpl-2.0.html>\n"
	       "This is free software: you are free to change and "
	       "redistribute it.\n"
	       "There is NO WARRANTY, to the extent permitted by law.\n",
	       VERSION);
}

/**
 * FIXME: implement this
 */
void
read_config_file(const std::string &fn)
{
	std::ifstream fi(fn.c_str());
	ConfigParser conf(fi);
	ConfigParser end;
	for (;conf != end; ++conf) {
		if (conf->keyword.empty()) {
			// empty
		} else if (conf->keyword == "#") {
			// comment
		} else if (conf->keyword == "Port") {
			options.port = conf->parms[0];
		} else if (conf->keyword == "ServerCAFile") {
			options.servercafile = conf->parms[0];
		} else if (conf->keyword == "ServerCAPath") {
			options.servercapath = conf->parms[0];
		} else if (conf->keyword == "CertFile") {
			options.certfile = xwordexp(conf->parms[0]);
		} else if (conf->keyword == "KeyFile") {
			options.keyfile = xwordexp(conf->parms[0]);
		} else if (conf->keyword == "CipherList") {
			options.cipher_list = conf->parms[0];
		} else if (conf->keyword == "-include") {
			try {
				read_config_file(xwordexp(conf->parms[0]));
			} catch(const ConfigParser::ErrStream&) {
				break;
			}
		} else if (conf->keyword == "include") {
			try {
				read_config_file(xwordexp(conf->parms[0]));
			} catch(const ConfigParser::ErrStream&) {
				throw "I/O error accessing config file: "
					+ conf->parms[0];
			}
		} else {
			throw "FIXME: error in config file: " + conf->keyword;
		}
	}
}

/**
 *
 */
void
parse_options(int argc, char * const *argv)
{
	int c;

	// expand default options. Not needed unless we change defaults
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
			options.config = argv[c+1];
		}
	}
	try {
		read_config_file(options.config);
	} catch(const ConfigParser::ErrStream&) {
		throw "I/O error accessing config file: " + options.config;
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

	if (optind + 1 != argc) {
		usage(1);
	}
	options.host = argv[optind];
}


END_NAMESPACE(tlssh);


BEGIN_LOCAL_NAMESPACE()
using namespace tlssh;
int
main2(int argc, char * const argv[])
{
	parse_options(argc, argv);

        if (SIG_ERR == signal(SIGWINCH, sigwinch)) {
                throw "FIXME: signal()";
        }

	sock.ssl_set_cipher_list(options.cipher_list);
	sock.ssl_set_capath(options.servercapath);
	sock.ssl_set_cafile(options.servercafile);
	sock.ssl_set_certfile(options.certfile);
	sock.ssl_set_keyfile(options.keyfile);
	if (options.verbose) {
		sock.set_debug(true);
	}

	Socket rawsock;

	rawsock.connect(options.host, options.port);
        rawsock.set_tcp_md5(options.tcp_md5);
        rawsock.set_tcp_md5_sock();
        rawsock.set_nodelay(true);
        rawsock.set_keepalive(true);
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
	} catch (const std::string &e) {
		std::cerr << "FIXME: " << std::endl
			  << e << std::endl;
	} catch (const char *e) {
		std::cerr << "FIXME: " << std::endl
			  << e << std::endl;
	}
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
