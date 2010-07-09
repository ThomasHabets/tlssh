/* tlssh/src/tlsshd-ssl.cc
 *
 * tlsshd
 *
 *   By Thomas Habets <thomas@habets.pp.se> 2010
 *
 * TLSSH SSLProc
 *
 * This file contains the code for the SSL-terminal "proxy"
 * process. It checks what user it should run as and then drops
 * privileges to that user. It also spawns the shell process.
 *
 * Then it shuffles data between the SSL socket and the user shell.
 *
 * [network] - <ssl socket> - [ssl] - <pty> - [shell]
 *                 ^            ^                ^
 *                 |            |                |
 * Code:        OpenSSL     This file        tlsshd-shell.cc & bash
 *
 * Some of this code is run as root. Those functions are clearly labeled.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<pty.h>
#include<utmp.h>
#include<unistd.h>
#include<grp.h>
#include<poll.h>
#include<pwd.h>
#include<arpa/inet.h>
#include<sys/stat.h>
#include<sys/types.h>

#include<iostream>

#include"tlssh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"
#include"configparser.h"
#include"util.h"

using namespace tlssh_common;
using tlsshd::options;

BEGIN_NAMESPACE(tlsshd_sslproc);

size_t iac_len[256];

/**
 * Run as: user
 */
std::string
parse_iac(FDWrap &fd, std::string &from_sock)
{
        std::string ret;
        size_t pos;

        const IACCommand *cmd;

        iac_len[1] = 6;

        for (;;) {
                // fast path: no IAC
                pos = from_sock.find('\xff');
                if (pos == std::string::npos) {
                        ret += from_sock;
                        from_sock = "";
                        break;
                }

                ret += from_sock.substr(0,pos);

                // no command yet
                if (from_sock.size() - 1 == pos) {
                        break;
                }

                cmd = reinterpret_cast<const IACCommand*>(from_sock.data());

                // incomplete command
                if (iac_len[cmd->s.command] > from_sock.size()) {
                        break;
                }

                switch (cmd->s.command) {
                case 255:
                        ret += "\xff";
                        break;
                case 1:
                        struct winsize ws;
                        ws.ws_col = ntohs(cmd->s.commands.ws.cols);
                        ws.ws_row = ntohs(cmd->s.commands.ws.rows);
                        if (0 > ioctl(fd.get(), TIOCSWINSZ, &ws)) {
                                throw "FIXME: ioctl(TIOCSWINSZ)";
                        }
                        break;
                default:
                        throw "FIXME: unknown IAC!";
                }
                from_sock.erase(0, iac_len[cmd->s.command]);
        }
        return ret;
}

/**
 * Run as: user
 */
bool
connect_fd_sock(FDWrap &fd,
		SSLSocket &sock,
		std::string &to_fd,
		std::string &from_sock,
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
			from_sock += sock.read();
		} while (sock.ssl_pending());
	}

        to_fd += parse_iac(fd, from_sock);

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

        // to client
	if ((fds[0].revents & POLLOUT)
	    && !to_sock.empty()) {
		size_t n;
		n = sock.write(to_sock);
		to_sock = to_sock.substr(n);
	}

        // to terminal
	if ((fds[1].revents & POLLOUT)
	    && !to_fd.empty()) {
		size_t n;
		n = fd.write(to_fd);
		to_fd = to_fd.substr(n);
	}

	return false;
}

/**
 * Run as: logged in user
 */
void
user_loop(FDWrap &terminal, SSLSocket &sock, FDWrap &control)
{
	std::string to_client;
	std::string to_terminal;
        std::string from_sock;

	int newlines = 0;
        for (;;) {
                std::string ch;
		ch = sock.read(1);
                if (ch == "\n") {
			newlines++;
		} else {
			newlines = 0;
		}
		control.full_write(ch);
		if (newlines == 2) {
			break;
		}
        }
        control.close();

        memset(iac_len, 2, sizeof(iac_len));
	for (;;) {
                if (connect_fd_sock(terminal,
                                    sock,
                                    to_client,
                                    from_sock,
                                    to_terminal)) {
                        break;
                }
	}
}


/**
 * Drop privs to logged in user
 */
void
drop_privs(const struct passwd *pw)
{
        if (initgroups(pw->pw_name, pw->pw_gid)) {
		throw "FIXME: initgroups()";
        }
#if 0
	if (0 > setgroups(0, NULL)) {
		throw "FIXME: setgroups()";
	}
#endif
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid)) {
		throw "FIXME: setresgid()";
	}
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) {
		throw "FIXME: setresuid()";
	}
}

/**
 * Run as: root
 * fork()s tlsshd_shellproc and drops privileges on both it and self.
 */
void
spawn_child(const struct passwd *pw,
	    pid_t *pid,
	    int *fdm,
	    int *fdm_control
            )
{
        int fd_control[2];

        if (chdir("/")) {
                THROW(Err::ErrSys, "chdir()");
        }
        if (pipe(fd_control)) {
                THROW(Err::ErrSys, "pipe()");

        }

        *pid = forkpty(fdm, NULL, NULL, NULL);
        if (*pid == -1) {
                THROW(Err::ErrSys, "forkpty()");
        }

        // child
        if (*pid == 0) {
                if (fchmod(0, 0600)) {
                        THROW(Err::ErrSys, "fchmod(0, 0600)");
                }
                if (fchown(0, pw->pw_uid, -1)) {
                        THROW(Err::ErrSys, "fchown(0, ...)");
                }

                close(fd_control[1]);
                drop_privs(pw);
                exit(tlsshd_shellproc::forkmain(pw, fd_control[0]));
	}

        // parent
        if (!options.chroot.empty()) {
                if (chroot(options.chroot.c_str())) {
                        THROW(Err::ErrSys, "chroot("+options.chroot+")");
                }
                if (chdir("/")) {
                        THROW(Err::ErrSys, "chdir(/)");
                }
        }
	drop_privs(pw);
        close(fd_control[0]);
        *fdm_control = fd_control[1];
}


/**
 * Run as: root
 *
 * verify cert information
 *
 * At this point the cert is guaranteed to be signed by the ClientCA.
 * We now check who the client subject is.
 */
void
new_ssl_connection(SSLSocket &sock)
{
	std::auto_ptr<X509Wrap> cert = sock.get_cert();
	if (!cert.get()) {
		sock.write("You are the no-cert client. Goodbye.");
                throw "FIXME: client provided no cert";
	}

	if (options.verbose) {
		std::cout << "Client cert: " << cert->get_subject()
			  << std::endl;
	}

	std::string certname = cert->get_common_name();
        size_t dotpos = certname.find('.');
        if (dotpos == std::string::npos) {
                throw "FIXME: cert CN had no dot";
        }
	std::string username = certname.substr(0, dotpos);
        std::string domain = certname.substr(dotpos+1);
        if (domain != options.clientdomain) {
                throw "FIXME: client is in wrong domain";
        }
        if (options.verbose) {
                printf("Logged in using cert: user=<%s>, domain=<%s>\n",
                       username.c_str(), domain.c_str());
        }

	std::vector<char> pwbuf;
	struct passwd pw = xgetpwnam(username, pwbuf);

	pid_t pid;
	int termfd;
        int fd_control;
	spawn_child(&pw, &pid, &termfd, &fd_control);
	FDWrap terminal(termfd);
	FDWrap control(fd_control);
	user_loop(terminal, sock, control);
}

/**
 * Run as: root
 *
 * At this point the only thing that's happened with the socket is that
 * it's been accept(2)ed. This function will SSL-wrap the socket and call
 * new_ssl_connection().
 *
 * input: newly connected fd, and newly forked process
 * output: calls new_ssl_connection() with up-and-running SSL connection
 */
int
forkmain(FDWrap&fd)
{
	try {
		SSLSocket sock(fd.get());
		fd.forget();

                sock.set_debug(options.verbose > 1);
                sock.set_nodelay(true);
                sock.set_keepalive(true);
                sock.set_tcp_md5(options.tcp_md5);
                sock.set_tcp_md5_sock();

                sock.ssl_set_crlfile(options.clientcrl);
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
		std::cerr << "sslproc: std::exception: "
			  << e.what() << std::endl;
	} catch (const char *e) {
		std::cerr << "FIXME: " << std::endl
			  << e << std::endl;
	} catch (...) {
		std::cerr << "Unknown exception happened\n";
	}
	return 0;
}

END_NAMESPACE(tlsshd_sslproc);
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
