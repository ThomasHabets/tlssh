#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<iostream>
#include <pty.h>

#include <utmp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/types.h>
#include <pwd.h>

#include"tlssh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"
#include"configparser.h"
#include"util.h"

using namespace tlssh_common;

BEGIN_NAMESPACE(tlsshd);

size_t iac_len[256];

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
user_loop(FDWrap &terminal, SSLSocket &sock, int fd_control)
{
	std::string to_client;
	std::string to_terminal;
        std::string from_sock;

        FDWrap control(fd_control);
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

void
spawn_child(const struct passwd *pw,
	    pid_t *pid,
	    int *fdm,
	    int *fdm_control
            )
{
        int fds;
        int fd_control[2];
	if (-1 == openpty(fdm, &fds, NULL, NULL, NULL)) {
                throw "FIXME: openpty()";
        }

	if (fchmod(fds, 0600)) {
		perror("fchmod(0, 0600)");
		exit(1);
	}

	if (fchown(fds, pw->pw_uid, -1)) {
		perror("fchown(0, pw->pw_uid, -1)");
		exit(1);
	}

        if (pipe(fd_control)) {
                throw "FIXME: pipe()";
        }

        *pid = fork();
	if (!*pid) {
                close(*fdm);
                close(fd_control[1]);
                if (-1 == login_tty(fds)) {
                        throw "FIXME: login_tty()";
                }
                drop_privs(pw);
                forkmain_child(pw, fd_control[0]);
	}
	drop_privs(pw);
        close(fd_control[0]);
        close(fds);
        *fdm_control = fd_control[1];
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
        int fd_control;
	spawn_child(&pw, &pid, &termfd, &fd_control);
	FDWrap terminal(termfd);
	user_loop(terminal, sock, fd_control);
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
                sock.set_nodelay(true);
                sock.set_keepalive(true);
                sock.set_tcp_md5(options.tcp_md5);
                sock.set_tcp_md5_sock();

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

END_NAMESPACE(tlsshd);
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
