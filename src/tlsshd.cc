/// tlssh/src/tlsshd.cc
/*
 *  tlsshd
 *
 *   By Thomas Habets <thomas@habets.pp.se> 2010
 *
 */
/**
 * @defgroup TLSSHD TLSSH Server
 @verbatim
  [network] - <ssl socket> - [ssl] - <pty> - [shell]
                  ^            ^                ^
                  |            |                |
   Code:        OpenSSL   tlsshd-ssl.cc    tlsshd-shell.cc & bash
@endverbatim
 *
 * @file src/tlsshd.cc
 * TLSSHD Listener process
 *
 * This process sets up the daemon, listens to the port and runs the
 * accept()-loop.
 *
 * All the code in this file runs as root.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<pwd.h>
#include<unistd.h>
#include<grp.h>
#include<poll.h>
#include<pty.h>
#include<utmp.h>
#include<signal.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>

#include<memory>
#include<iostream>
#include<fstream>
#include<vector>

#include"tlssh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"
#include"configparser.h"
#include"util.h"

using namespace tlssh_common;
using namespace Err;

BEGIN_NAMESPACE(tlsshd);

/* constants */
const char *argv0 = NULL;

const std::string DEFAULT_PORT         = "12345";
const std::string DEFAULT_CERTFILE     = "/etc/tlssh/tlsshd.crt";
const std::string DEFAULT_KEYFILE      = "/etc/tlssh/tlsshd.key";
const std::string DEFAULT_CLIENTCAFILE = "/etc/tlssh/ClientCA.crt";
const std::string DEFAULT_CLIENTCRL    = "/etc/tlssh/ClientCRL.pem";
const std::string DEFAULT_CLIENTCAPATH = "";
const std::string DEFAULT_CLIENTDOMAIN = "";
const std::string DEFAULT_CONFIG       = "/etc/tlssh/tlsshd.conf";
const std::string DEFAULT_CIPHER_LIST  = "HIGH:!ADH:!LOW:!MD5:@STRENGTH";
const std::string DEFAULT_TCP_MD5      = "tlssh";
const std::string DEFAULT_CHROOT       = "/var/empty";
const unsigned    DEFAULT_VERBOSE      = 0;
const bool        DEFAULT_DAEMON       = true;
const int         DEFAULT_AF           = AF_UNSPEC;

/* Process-wide variables */

Socket listen;
std::string protocol_version; // should be "tlssh.1"

Options options = {
 port:           DEFAULT_PORT,
 certfile:       DEFAULT_CERTFILE,
 keyfile:        DEFAULT_KEYFILE,
 clientcafile:   DEFAULT_CLIENTCAFILE,
 clientcrl:      DEFAULT_CLIENTCRL,
 clientcapath:   DEFAULT_CLIENTCAPATH,
 clientdomain:   DEFAULT_CLIENTDOMAIN,
 config:         DEFAULT_CONFIG,
 cipher_list:    DEFAULT_CIPHER_LIST,
 tcp_md5:        DEFAULT_TCP_MD5,
 chroot:         DEFAULT_CHROOT,
 verbose:        DEFAULT_VERBOSE,
 daemon:         DEFAULT_DAEMON,
 af:             DEFAULT_AF,
};

/** Listen-loop.
 *
 * Run as: root
 *
 * Run accept() in a loop. Do not read or write to the socket.
 * spawns a newly fork()ed sslproc handler. (tlsshd-ssl.cc::forkmain())
 *
 * @return Never returns, but if it did it would be the process exit value.
 */
int
listen_loop()
{
        struct sockaddr_storage sa; // never read from

	for (;;) {
		FDWrap clifd;
                pid_t pid;
		socklen_t salen = sizeof(sa); 

		clifd.set(::accept(listen.getfd(),
                                   (struct sockaddr*)&sa,
                                   &salen));
		if (0 > clifd.get()) {
			continue;
		}

                pid = fork();

                if (0 > pid) {          // error
                        fprintf(stderr, "%s: fork() failed", argv0);
                } else if (pid == 0) {  // child
                        listen.close();
			exit(tlsshd_sslproc::forkmain(clifd));
		} else {
                        ;
                }
	}
}

/** Print usage info and exit.
 *
 * Called when doing one of:
 * -h option (err = 0) 
 * --help option (err = 0)
 * invalid options (err != 1)
 */
void
usage(int err)
{
	printf("%s [ -46fhv ] "
	       "[ -c <config> ] "
	       "[ -C <cipher-list> ] "
	       "[ -p <cert+keyfile> ]"
	       "\n"
	       "\t-c <config>          Config file (default %s)\n"
	       "\t-C <cipher-list>     Acceptable ciphers (default %s)\n"
	       "\t-f                   Run in foreground\n"
	       "\t-h, --help           Help\n"
	       "\t-V, --version        Print version and exit\n"
	       "\t-p <cert+keyfile>    Load login cert+key from file\n"
	       , argv0,
               DEFAULT_CONFIG.c_str(),
               DEFAULT_CIPHER_LIST.c_str());
	exit(err);
}

/** Print version info like GNU wants it. Caller exit()s
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

/** Read config file
 *
 */
void
read_config_file(const std::string &fn)
{
	std::ifstream fi(fn.c_str());
	ConfigParser conf(fi);
	ConfigParser end;
	for (;conf != end; ++conf) {
		if (conf->keyword.empty()) {
			// empty line
		} else if (conf->keyword[0] == '#') {
			// comment
		} else if (conf->keyword == "ClientCAFile"
                           && conf->parms.size() == 1) {
			options.clientcafile = conf->parms[0];
		} else if (conf->keyword == "ClientCAPath"
                           && conf->parms.size() == 1) {
			options.clientcapath = conf->parms[0];
		} else if (conf->keyword == "ClientCRL"
                           && conf->parms.size() == 1) {
			options.clientcrl = conf->parms[0];
		} else if (conf->keyword == "ClientDomain"
                           && conf->parms.size() == 1) {
			options.clientdomain = conf->parms[0];
		} else if (conf->keyword == "Chroot"
                           && conf->parms.size() == 1) {
			options.chroot = conf->parms[0];
		} else if (conf->keyword == "Port"
                           && conf->parms.size() == 1) {
			options.port = conf->parms[0];
		} else if (conf->keyword == "KeyFile"
                           && conf->parms.size() == 1) {
			options.keyfile = conf->parms[0];
		} else if (conf->keyword == "CertFile"
                           && conf->parms.size() == 1) {
			options.certfile = conf->parms[0];
		} else if (conf->keyword == "CipherList"
                           && conf->parms.size() == 1) {
			options.cipher_list = conf->parms[0];
		} else if (conf->keyword == "-include"
                           && conf->parms.size() == 1) {
			try {
				read_config_file(xwordexp(conf->parms[0]));
			} catch(const ConfigParser::ErrStream&) {
                                // -includes don't have to work
				break;
			}
		} else if (conf->keyword == "include"
                           && conf->parms.size() == 1) {
			try {
				read_config_file(xwordexp(conf->parms[0]));
			} catch(const ConfigParser::ErrStream&) {
				THROW(ErrBase,
                                      "I/O error accessing include file: "
                                      + conf->parms[0]);
			}
		} else {
                        THROW(ErrBase,
                              "Error in config line: " + conf->line);
		}
	}
}

/**
 * Parse command line options. First read config file and then let cmdline
 * override that.
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
                THROW(ErrBase,
                      "I/O error accessing config file: "
                      + options.config);
	}

	int opt;
	while ((opt = getopt(argc, argv, "46c:C:fhp:vV")) != -1) {
		switch (opt) {
                case '4':
                        options.af = AF_INET;
                        break;
                case '6':
                        options.af = AF_INET6;
                        break;
		case 'c':
			// already handled above
			break;
		case 'C':
			options.cipher_list = optarg;
			break;
		case 'f':
                        options.daemon = false;
			break;
		case 'h':
			usage(0);
		case 'p':
			options.keyfile = optarg;
			options.certfile = optarg;
			exit(0);
		case 'v':
			options.verbose++;
                        break;
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
 * wrapped main() so that we don't have to handle exceptions in this main()
 */
int
main2(int argc, char * const argv[])
{
        if (SIG_ERR == signal(SIGCHLD, SIG_IGN)) {
                THROW(Err::ErrBase, "signal(SIGCHLD, SIG_IGN)");
        }

	parse_options(argc, argv);
        //tlsshd::listen.set_tcp_md5(options.tcp_md5);
	tlsshd::listen.listen_any(options.af, options.port);

        if (options.daemon) {
                if (daemon(0,0)) {
                        THROW(Err::ErrSys, "daemon(0, 0)");
                }
        }
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
	} catch (const Err::ErrBase &e) {
                if (options.verbose) {
                        fprintf(stderr, "%s: %s\n",
                                argv0, e.what_verbose().c_str());
                } else {
                        fprintf(stderr, "%s: %s\n",
                                argv0, e.what());
                }
	} catch (const std::exception &e) {
		std::cerr << "tlsshd std::exception: "
			  << e.what() << std::endl;
	} catch (const char *e) {
		std::cerr << "tlsshd const char*: "
			  << e << std::endl;
	} catch (...) {
		std::cerr << "tlsshd: Unknown exception!" << std::endl;
                throw;
	}
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
