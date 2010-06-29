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


#include<poll.h>
#include<pty.h>

#include<memory>
#include<iostream>
#include<fstream>
#include<vector>


#include"tlssh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"
#include"configparser.h"
#include"util.h"


/**
 *
 */
struct passwd
xgetpwnam(const std::string &name, std::vector<char> &buffer)
{
	buffer.reserve(1024);
	struct passwd pw;
	struct passwd *ppw = 0;
	if (xgetpwnam_r(name.c_str(), &pw, &buffer[0], buffer.capacity(), &ppw)
	    || !ppw) {
		throw "FIXME";
	}

	return pw;
}

BEGIN_NAMESPACE(tlsshd);

// constants

const std::string DEFAULT_PORT         = "12345";
const std::string DEFAULT_CERTFILE     = "/etc/tlssh/tlsshd.crt";
const std::string DEFAULT_KEYFILE      = "/etc/tlssh/tlsshd.key";
const std::string DEFAULT_CLIENTCAFILE = "/etc/tlssh/ClientCA.crt";
const std::string DEFAULT_CLIENTCAPATH = "";
const std::string DEFAULT_CONFIG       = "/etc/tlssh/tlsshd.conf";
const std::string DEFAULT_CIPHER_LIST  = "DHE-RSA-AES256-SHA";

//  Structs

struct Options {
	std::string port;
	std::string certfile;
	std::string keyfile;
	std::string clientcafile;
	std::string clientcapath;
	std::string config;
	std::string cipher_list;
};

// Process-wide variables

Socket listen;

Options options = {
 port:           DEFAULT_PORT,
 certfile:       DEFAULT_CERTFILE,
 keyfile:        DEFAULT_KEYFILE,
 clientcafile:   DEFAULT_CLIENTCAFILE,
 clientcapath:   DEFAULT_CLIENTCAPATH,
 config:         DEFAULT_CONFIG,
 cipher_list:    DEFAULT_CIPHER_LIST
};
	

/**
 *
 */
void
drop_privs(const struct passwd *pw)
{
	if (0 > setgroups(0, NULL)) {
		throw "FIXME: setgroups()";
	}
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid)) {
		throw "FIXME: setresgid()";
	}
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) {
		throw "FIXME: setresuid()";
	}
}

bool
connect_fd_sock(FDWrap &fd,
		SSLSocket &sock,
		std::string &to_fd,
		std::string &to_sock)
{
	struct pollfd fds[2];
	bool active[2] = {true, true};
	int err;

	fds[0].fd = sock.getfd();
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	if (!to_sock.empty()) {
		fds[0].events |= POLLOUT;
	}
	if (fds[0].fd < 0) {
		active[0] = false;
	}

	fds[1].fd = fd.get();
	fds[1].events = POLLIN;
	fds[0].revents = 1;
	if (!to_fd.empty()) {
		fds[1].events |= POLLOUT;
	}
	if (fds[1].fd < 0) {
		active[1] = false;
	}

	// if both sockets closed, return done
	if (!active[0]
	    && !active[1]) {
		return true;
	}

	if (!active[0]) {
		err = poll(&fds[1], 1, 1000);
	} if (!active[1]) {
		err = poll(fds, 1, 1000);
	} else {
		err = poll(fds, 2, 1000);
	}

	if (!err) { // timeout
		return false;
	}
	if (0 > err) { // error
		return false;
	}

	// from client
	if (fds[0].revents & POLLIN) {
		do {
			to_fd += sock.read();
		} while (sock.ssl_pending());
	}

	// from shell
	if (fds[1].revents & POLLIN) {
		to_sock += fd.read();
	}

	// shell exited
	if (fds[1].revents & POLLHUP) {
		fd.close();
		fds[1].revents = 0;
		active[1] = false;
	}
	// if shell has exited and 
	if (!active[1] && to_sock.empty()) {
		return true;
	}

	// output
	if ((fds[0].revents & POLLOUT)
	    && !to_sock.empty()) {
		size_t n;
		n = sock.write(to_sock);
		to_sock = to_sock.substr(n);
	}

	if ((fds[1].revents & POLLOUT)
	    && !to_fd.empty()) {
		size_t n;
		n = fd.write(to_fd);
		to_fd = to_fd.substr(n);
	}

	return false;
}

void
user_loop(FDWrap &terminal, SSLSocket &sock)
{
	std::string to_client;
	std::string to_terminal;
	for (;;) {
		if (connect_fd_sock(terminal, sock, to_client, to_terminal)) {
			break;
		}
	}
}

/**
 *
 */
void
forkmain_child(const struct passwd *pw)
{
	if (fchmod(0, 0600)) {
		perror("fchmod(0, 0600)");
		exit(1);
	}

	if (fchown(0, pw->pw_uid, -1)) {
		perror("fchown(0, pw->pw_uid, -1)");
		exit(1);
	}

	if (clearenv()) {
		perror("clearenv()");
		exit(1);
	}

	if (setenv("HOME", pw->pw_dir, 1)) {
		perror("setenv(HOME, pw->pw_dir, 1)");
		exit(1);
	}

	if (chdir(pw->pw_dir)) {
		perror("chdir(user home directory)");
		exit(1);
	}

	drop_privs(pw);

	execl(pw->pw_shell, pw->pw_shell, "-i", NULL);

	// Should never be reached

	perror("execl()");
	exit(1);
}

void
spawn_child(const struct passwd *pw,
	    pid_t *pid,
	    int *fdm)
{
	*pid = forkpty(fdm, NULL, NULL, NULL);

	if (!*pid) {
		forkmain_child(pw);
	}
	drop_privs(pw);
}

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

	if (0) {
		std::cout << "Client cert: " << cert->get_subject()
			  << std::endl;
	}

	std::string username = cert->get_common_name();
	std::cout << "Logged in using cert " << username << std::endl;
	username = username.substr(0,username.find('.'));

	std::vector<char> pwbuf;
	struct passwd pw = xgetpwnam(username, pwbuf);

	pid_t pid;
	int termfd;
	spawn_child(&pw, &pid, &termfd);
	FDWrap terminal(termfd);
	user_loop(terminal, sock);
}

/**
 *
 * input: newly connected fd, and newly forked process
 * output: calls new_ssl_connection() with up-and-running SSL connection
 */
int
forkmain_new_connection(FDWrap&fd)
{
	try {
		SSLSocket sock(fd.get());
		fd.forget();
		sock.ssl_set_cipher_list(options.cipher_list);
		sock.ssl_set_capath(options.clientcapath);
		sock.ssl_set_cafile(options.clientcafile);
		sock.ssl_set_certfile(options.certfile);
		sock.ssl_set_keyfile(options.keyfile);

		sock.ssl_accept();
		new_ssl_connection(sock);
	} catch (const SSLSocket::ErrSSL &e) {
		std::cerr << e.human_readable();
	} catch (const std::exception &e) {
		std::cerr << "forkmain_new_connection std::exception: "
			  << e.what() << std::endl;
	} catch (const char *e) {
		std::cerr << "FIXME: " << std::endl
			  << e << std::endl;
	} catch (...) {
		std::cerr << "Unknown exception happened\n";
	}
	return 0;
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
			exit(forkmain_new_connection(clifd));
		} else {
			clifd.close();
		}
	}
}

void
usage(int err)
{
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
		} else if (!strcmp(argv[c], "--version")) {
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
	while ((opt = getopt(argc, argv, "c:hv")) != -1) {
		switch (opt) {
		case 'c':
			// already handled above
			break;
		default:
			usage(1);
		}
	}
}

END_NAMESPACE(tlsshd);

BEGIN_LOCAL_NAMESPACE()
using namespace tlsshd;
int
main2(int argc, char * const argv[])
{
	parse_options(argc, argv);
	tlsshd::listen.listen_any(atoi(options.port.c_str()));

	return listen_loop();
}
END_LOCAL_NAMESPACE()

int
main(int argc, char **argv)
{
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
