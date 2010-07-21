/// tlssh/src/tlsshd-ssl.cc
/**
 * @addtogroup TLSSHD
 * @file src/tlsshd-ssl.cc
 * TLSSHD SSL middle-layer process.
 *
 * TLSSH SSLProc
 *
 * This file contains the code for the SSL-terminal "proxy"
 * process. It checks what user it should run as and then drops
 * privileges to that user. It also spawns the shell process.
 *
 * Then it shuffles data between the SSL socket and the user shell.
 *
 * Some of this code is run as root. Those functions are clearly labeled.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_PTY_H
#include<pty.h>
#endif
#include<time.h>
#include<utmp.h>
#include<unistd.h>
#include<grp.h>
#include<poll.h>
#include<pwd.h>
#include<arpa/inet.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<termios.h>

#include<iostream>

#include"tlssh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"
#include"configparser.h"
#include"util.h"

using namespace tlssh_common;
using tlsshd::options;

BEGIN_NAMESPACE(tlsshd_sslproc);

FDWrap fd_wtmp;
std::string short_ttyname;
std::string short2_ttyname;

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
                                THROW(Err::ErrSys, "ioctl(TIOCSWINSZ)");
                        }
                        break;
                default:
                        THROW(Err::ErrBase, "Unknown IAC!");
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
		THROW(Err::ErrSys, "initgroups()");
        }
#if 0
	if (0 > setgroups(0, NULL)) {
		THROW(Err::ErrSys, "setgroups()");
	}
#endif
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid)) {
		THROW(Err::ErrSys, "setresgid()");
	}
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) {
		THROW(Err::ErrSys, "setresuid()");
	}
}

/**
 * Log user login to utmp and wtmp.
 *
 * Run as: root
 */
void
log_login(const struct passwd *pw, const std::string &peer_addr)
{
#if 0
        struct utmp ut;
        // write to utmp file (who / w)
        if (1) {
                struct timeval tv;
                memset(&ut, 0, sizeof(ut));
                ut.ut_type = USER_PROCESS;
                ut.ut_pid = getpid();
                strncpy(ut.ut_line,
                        short_ttyname.c_str(),
                        sizeof(ut.ut_line) - 1);
                strncpy(ut.ut_id,
                        short2_ttyname.c_str(),
                        sizeof(ut.ut_id) - 1);
                gettimeofday(&tv, NULL);
                ut.ut_tv.tv_sec = tv.tv_sec;
                ut.ut_tv.tv_usec = tv.tv_usec;
                strncpy(ut.ut_user,
                        pw->pw_name,
                        sizeof(ut.ut_user) - 1);
                strncpy(ut.ut_host,
                        peer_addr.c_str(),
                        sizeof(ut.ut_host) - 1);
                ut.ut_addr = 0;
                setutent();
                if (!pututline(&ut)) {
                        THROW(Err::ErrSys, "pututline()");
                }
                endutent();
        }

        // write to wtmp file (last -10)
        if (1) {
                logwtmp(short_ttyname.c_str(),
                        pw->pw_name,
                        peer_addr.c_str());
        }
#endif
}

/**
 * Write logout info to wtmp
 *
 * @todo This is not pretty. I feel like it at least needs locking.
 *       What I'd really like is a updwtmp() that uses FILE* or int fd.
 */
void
log_logout()
{
#if 0
        if (!fd_wtmp.valid()) {
                return;
        }

        struct utmp ut;
        memset(&ut, 0, sizeof(ut));
        strncpy(ut.ut_line, short_ttyname.c_str(), sizeof(ut.ut_line)-1);
        ut.ut_time = time(0);
        //ut.ut_type = DEAD_PROCESS; // Linux-specific?
        fd_wtmp.full_write(std::string((char*)&ut,
                                       ((char*)&ut) + sizeof(ut)));
#endif
}

/**
 * fork()s tlsshd_shellproc and drops privileges on both it and self.
 *
 * Run as: root
 */
void
spawn_child(const struct passwd *pw,
	    pid_t *pid,
	    int *fdm,
	    int *fdm_control,
            const std::string &peer_addr
            )
{
        int fd_control[2];
        char tty_name[PATH_MAX];

        if (chdir("/")) {
                THROW(Err::ErrSys, "chdir()");
        }
        if (pipe(fd_control)) {
                THROW(Err::ErrSys, "pipe()");

        }

        *pid = forkpty(fdm, tty_name, NULL, NULL);
        if (*pid == -1) {
                THROW(Err::ErrSys, "forkpty()");
        }

        short_ttyname = tty_name;

        if (short_ttyname.substr(0,5) == "/dev/") {
                short_ttyname = short_ttyname.substr(5);
        }

        short2_ttyname = gnustyle_basename(short_ttyname.c_str());
        if (short2_ttyname.substr(0,3) == "tty") {
                short2_ttyname = short2_ttyname.substr(3);
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

                log_login(pw, peer_addr);

                drop_privs(pw);
                exit(tlsshd_shellproc::forkmain(pw, fd_control[0]));
	}

        fd_wtmp.set(open(WTMP_FILE, O_WRONLY | O_APPEND));

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
                THROW(Err::ErrBase, "client provided no cert");
	}

        logger->debug("Client cert: %s", cert->get_subject().c_str());

	std::string certname = cert->get_common_name();
        size_t dotpos = certname.find('.');
        if (dotpos == std::string::npos) {
                THROW(Err::ErrBase, "cert CN had no dot");
        }
	std::string username = certname.substr(0, dotpos);
        std::string domain = certname.substr(dotpos+1);
        if (domain != options.clientdomain) {
                THROW(Err::ErrBase, "client is in wrong domain");
        }

        logger->info("Logged in using cert: user=<%s>, domain=<%s>",
                    username.c_str(), domain.c_str());

	std::vector<char> pwbuf;
	struct passwd pw = xgetpwnam(username, pwbuf);

	pid_t pid;
	int termfd;
        int fd_control;
	spawn_child(&pw, &pid, &termfd, &fd_control,
                    sock.get_peer_addr_string());
	FDWrap terminal(termfd);
	FDWrap control(fd_control);
	user_loop(terminal, sock, control);

        log_logout();
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
 *
 * @todo Eventually don't catch const char*
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
	} catch (const SSLSocket::ErrSSLHostname &e) {
		logger->warning("%s", e.what());
	} catch (const SSLSocket::ErrSSLCRL &e) {
		logger->warning("%s", e.what());
	} catch (const SSLSocket::ErrSSL &e) {
		logger->warning("%s", e.what_verbose().c_str());
	} catch (const std::exception &e) {
                logger->err("%s",
                            (std::string("sslproc: std::exception: ")
                             + e.what() + "\n").c_str());
	} catch (const char *e) {
		logger->err("%s", (std::string("FIXME: ") + e).c_str());
	} catch (...) {
		logger->err("Unknown exception happened");
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
