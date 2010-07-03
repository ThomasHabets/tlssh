// tlsshd/src/tlsshd.cc
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<sys/types.h>
#include<pwd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<unistd.h>
#include<grp.h>
#include<arpa/inet.h>


#include<poll.h>
#include<pty.h>

#include<memory>
#include<iostream>
#include<fstream>
#include<vector>
#include <utmp.h>


#include"tlssh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"
#include"configparser.h"
#include"util.h"

using namespace tlssh_common;

BEGIN_NAMESPACE(tlsshd);

// constants
const char *argv0 = NULL;

const std::string DEFAULT_PORT         = "12345";
const std::string DEFAULT_CERTFILE     = "/etc/tlssh/tlsshd.crt";
const std::string DEFAULT_KEYFILE      = "/etc/tlssh/tlsshd.key";
const std::string DEFAULT_CLIENTCAFILE = "/etc/tlssh/ClientCA.crt";
const std::string DEFAULT_CLIENTCAPATH = "";
const std::string DEFAULT_CONFIG       = "/etc/tlssh/tlsshd.conf";
const std::string DEFAULT_CIPHER_LIST  = "DHE-RSA-AES256-SHA";
const std::string DEFAULT_TCP_MD5      = "tlssh";
const std::string DEFAULT_CHROOT       = "/var/empty";

//  Structs


// Process-wide variables

Socket listen;
std::string protocol_version; // "tlssh.1"


Options options = {
 port:           DEFAULT_PORT,
 certfile:       DEFAULT_CERTFILE,
 keyfile:        DEFAULT_KEYFILE,
 clientcafile:   DEFAULT_CLIENTCAFILE,
 clientcapath:   DEFAULT_CLIENTCAPATH,
 config:         DEFAULT_CONFIG,
 cipher_list:    DEFAULT_CIPHER_LIST,
 tcp_md5:        DEFAULT_TCP_MD5,
 chroot:         DEFAULT_CHROOT,
};
	
/**
 *
 */
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
			exit(tlsshd_sslproc::forkmain(clifd));
		} else {
			clifd.close();
		}
	}
}

/**
 *
 */
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

/**
 *
 */
void
printversion()
{
	printf("tlsshd %s\n"
	       "Copyright (C) 2010 Thomas Habets <thomas@habets.pp.se>\n"
	       "License GPLv2: GNU GPL version 2 or later "
	       "<http://gnu.org/licenses/gpl-2.0.html>\n"
	       "This is free software: you are free to change and "
	       "redistribute it.\n"
	       "There is NO WARRANTY, to the extent permitted by law.\n",
	       VERSION);
}

/**
 * FIXME: check parms count
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
		} else if (conf->keyword == "ClientCAFile") {
			options.clientcafile = conf->parms[0];
		} else if (conf->keyword == "ClientCAPath") {
			options.clientcapath = conf->parms[0];
		} else if (conf->keyword == "Port") {
			options.port = conf->parms[0];
		} else if (conf->keyword == "KeyFile") {
			options.keyfile = conf->parms[0];
		} else if (conf->keyword == "CertFile") {
			options.certfile = conf->parms[0];
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
 * FIXME: this is just a skeleton
 */
void
parse_options(int argc, char * const *argv)
{
	int c;

	/* special options */
	for (c = 1; c < argc - 1; c++) {
		if (!strcmp(argv[c], "--")) {
			break;
		} else if (!strcmp(argv[c], "--help")) {
			usage(0);
		} else if (!strcmp(argv[c], "--version")) {
			printversion();
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
	while ((opt = getopt(argc, argv, "c:hp:vV")) != -1) {
		switch (opt) {
		case 'h':
			usage(0);
		case 'c':
			// already handled above
			break;
		case 'p':
			options.keyfile = optarg;
			options.certfile = optarg;
			exit(0);
		case 'V':
			printversion();
			exit(0);
		default:
			usage(1);
		}
	}
}

END_NAMESPACE(tlsshd);

BEGIN_LOCAL_NAMESPACE()
using namespace tlsshd;
/**
 *
 */
int
main2(int argc, char * const argv[])
{
	parse_options(argc, argv);
        tlsshd::listen.set_tcp_md5("foo");
	tlsshd::listen.listen_any(atoi(options.port.c_str()));

	return listen_loop();
}
END_LOCAL_NAMESPACE()

/**
 *
 */
int
main(int argc, char **argv)
{
	argv0 = argv[0];
	try {
		return main2(argc, argv);
	} catch (const std::exception &e) {
		std::cout << "tlsshd::main() std::exception: "
			  << e.what() << std::endl;
	} catch (const std::string &e) {
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
