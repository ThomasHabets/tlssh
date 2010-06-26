// sslshd/src/sslshd.cc
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
#include<vector>


#include"sslsh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"


/**
 * FIXME; make reentrant
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

BEGIN_NAMESPACE(sslshd);

struct Options {
	std::string port;
	std::string certfile;
	std::string keyfile;
	std::string cafile;
	std::string capath;
};
Options options = {
 port: "12345",
 certfile: "green.crap.retrofitta.se.crt",
 keyfile: "green.crap.retrofitta.se.key",
 cafile: "client-ca.crt",
};
	
Socket listen;

void
drop_privs(const struct passwd *pw)
{
	if (setgroups(0, NULL)) {
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

void
spawn_shell(const struct passwd *pw,
	    pid_t *pid,
	    int *fdm)
{
	*pid = forkpty(fdm, NULL, NULL, NULL);

	if (!*pid) {
		fchmod(0, 0600);
		fchown(0, pw->pw_uid, -1);
		clearenv();
		setenv("HOME", pw->pw_dir, 1);
		chdir(pw->pw_dir);
		drop_privs(pw);
		execl(pw->pw_shell, pw->pw_shell, "-i", NULL);
		perror("execl()");
		exit(1);
	}
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

	std::cout << "Client cert: " << cert->get_subject() << std::endl;

	std::string username = cert->get_common_name();
	std::cout << "  Logged in using cert " << username << std::endl;
	username = username.substr(0,username.find('.'));
	std::cout << "  username " << username << std::endl;

	std::vector<char> pwbuf;
	struct passwd pw = xgetpwnam(username, pwbuf);

	pid_t pid;
	int termfd;
	spawn_shell(&pw, &pid, &termfd);
	FDWrap terminal(termfd);
	user_loop(terminal, sock);
	printf("---------\n");
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
				options.keyfile,
				options.cafile,
				options.capath
				);
		new_ssl_connection(sock);
	} catch (const std::exception &e) {
		std::cerr << "std::exception: " << e.what() << std::endl;
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
