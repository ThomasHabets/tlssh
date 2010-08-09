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

#ifdef HAVE_PTY_H
#include<pty.h>
#endif

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
#include"util2.h"

using namespace tlssh_common;
using namespace Err;

Logger *logger;

BEGIN_NAMESPACE(tlsshd);

/* constants */
const char *argv0 = NULL;

const std::string DEFAULT_LISTEN       = "::";
const std::string DEFAULT_PORT         = "12345";
const std::string DEFAULT_CERTFILE     = "/etc/tlssh/tlsshd.crt";
const std::string DEFAULT_KEYFILE      = "/etc/tlssh/tlsshd.key";
const std::string DEFAULT_CLIENTCAFILE = "/etc/tlssh/ClientCA.crt";
const std::string DEFAULT_CLIENTCRL    = "";
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
 listen:         DEFAULT_LISTEN,
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

/** SIGINT handler
 *
 * Listener process just quits if it gets SIGINT.
 * Ongoing connections do not. pkill -INT tlsshd is therefore safe in
 * that it will not cause you to shoot down the connection you are
 * using.
 *
 * @todo Find a clean way to always log a message here
 */
void
sigint(int)
{
        _exit(1);
}

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
                        logger->err("accept()-loop fork() failed");
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
        printf("%s [ -46fhvV ] "
	       "[ -c <config> ] "
	       "[ -C <cipher-list> ] "
               "\n"
               "\t[ -p <cert+keyfile> ]"
	       "\n"
	       "\t-c <config>          Config file (default %s)\n"
               "\t-C <cipher-list>     Acceptable ciphers\n"
               "\t                     (default %s)\n"
	       "\t-f                   Run in foreground\n"
	       "\t-h, --help           Help\n"
	       "\t-V, --version        Print version and exit\n"
	       "\t-p <cert+keyfile>    Load login cert+key from file\n"
	       , argv0,
               DEFAULT_CONFIG.c_str(),
               DEFAULT_CIPHER_LIST.c_str());
	exit(err);
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
		} else if (conf->keyword == "Listen"
                           && conf->parms.size() == 1) {
			options.listen = conf->parms[0];
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
	for (c = 1; c < argc; c++) {
		if (!strcmp(argv[c], "--")) {
			break;
		} else if (!strcmp(argv[c], "--help")
                           || !strcmp(argv[c], "-h")) {
			usage(0);
		} else if (!strcmp(argv[c], "--version")
                           || !strcmp(argv[c], "-V")) {
			print_version();
			exit(0);
		} else if (!strcmp(argv[c], "--copying")) {
			print_copying();
			exit(0);
		} else if (!strcmp(argv[c], "-c")) {
                        if (c + 1 != argc) {
                                options.config = argv[c+1];
                        }
		}
	}
	try {
		read_config_file(options.config);
	} catch(const ConfigParser::ErrStream&) {
                THROW(ErrBase,
                      "I/O error accessing config file: "
                      + options.config + "\n"
                      + "tlsshd requires a valid config file.");
	}

	int opt;
	while ((opt = getopt(argc, argv, "c:fhvV")) != -1) {
		switch (opt) {
		case 'c':
			// already handled above
			break;
		case 'f':
                        options.daemon = false;
			break;
		case 'h':
			usage(0);
		case 'v':
			options.verbose++;
                        break;
		case 'V':
			print_version();
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
 *
 * @todo Only listen to options.listen
 */
int
main2(int argc, char * const argv[])
{
        if (SIG_ERR == signal(SIGCHLD, SIG_IGN)) {
                THROW(Err::ErrBase, "signal(SIGCHLD, SIG_IGN)");
        }

        if (SIG_ERR == signal(SIGINT, sigint)) {
                THROW(Err::ErrBase, "signal(SIGINT, sigint)");
        }

	parse_options(argc, argv);
        if (options.verbose) {
                logger->set_logmask(logger->get_logmask()
                                    | LOG_MASK(LOG_DEBUG));
        }
        //tlsshd::listen.set_tcp_md5(options.tcp_md5);
	tlsshd::listen.listen(options.af, options.listen, options.port);

        if (options.daemon) {
                if (daemon(0,0)) {
                        THROW(Err::ErrSys, "daemon(0, 0)");
                }
                if (options.daemon) {
                        logger->set_copyterminal(false);
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
        if (getuid()) {
                fprintf(stderr, "tlsshd must run as root\n");
                exit(1);
        }

        logger = new SysLogger("tlsshd", LOG_AUTHPRIV);
        logger->set_copyterminal(true);
        logger->set_logmask(logger->get_logmask() & ~LOG_MASK(LOG_DEBUG));

	argv0 = argv[0];
	try {
		return main2(argc, argv);
	} catch (const Err::ErrBase &e) {
                if (options.verbose) {
                        logger->err("%s", e.what_verbose().c_str());
                } else {
                        logger->err("%s", e.what());
                }
	} catch (const std::exception &e) {
		logger->err("tlsshd std::exception: %s", e.what());
	} catch (...) {
		logger->err("tlsshd: Unknown exception!");
                throw;
	}
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
