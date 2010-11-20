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
 *
 * Note that even though this process runs as the end-user we do *not*
 * want it to have security holes. This process has the SSL private
 * key in memory and there is apparently no way to scrub it, even if
 * we give up the possibility to renegotiate.
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
#include<limits.h>
#include<stdlib.h>
#include<grp.h>
#include<poll.h>
#include<pwd.h>
#include<arpa/inet.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/ioctl.h>
#include<fcntl.h>
#include<termios.h>
#include<signal.h>

#ifdef HAVE_UTMPX_H
#include<utmpx.h>
#endif

#ifdef HAVE_UTMP_H
#include<utmp.h>
#endif

#ifdef HAVE_UTIL_H
#include<util.h>
#endif

#include<iostream>

#include"../monotonic_clock/include/monotonic_clock.h"

#include"tlssh.h"
#include"sslsocket.h"
#include"xgetpwnam.h"
#include"configparser.h"
#include"util2.h"

// OpenBSD
#ifndef WTMP_FILE
#define WTMP_FILE _PATH_WTMP
#endif

using namespace tlssh_common;
using tlsshd::options;

BEGIN_NAMESPACE(tlsshd_sslproc);

FDWrap fd_wtmp;
std::string short_ttyname;
std::string short2_ttyname;

/**
 * Run as: user
 *
 * @return true if all done
 */
bool
connect_fd_sock(FDWrap &fd,
		SSLSocket &sock,
		std::string &to_fd,
		std::string &from_sock,
		std::string &to_sock)
{
	struct pollfd fds[2];
	bool active[2] = {true, true}; // terminal, client
	int err;
        double now;
        static double last_keepalive_sent = 0;

        if (options.keepalive != 0) {
                now = clock_get_dbl();
                if (last_keepalive_sent + options.keepalive < now) {
                        last_keepalive_sent = now;
                        to_sock += iac_echo_request((uint32_t)now);
                }
        }

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

	// if shell has exited and there's nothing more to write to socket
	if (!active[1] && to_sock.empty()) {
		return true;
	}

        int timeout = -1;
        if (options.keepalive != 0) {
                timeout = 1000 * (options.keepalive
                                  - (now - last_keepalive_sent));
                // protect against rounding errors
                timeout = std::max(timeout, 0);
        }

        // FIXME: why do we wait at most 1s?
        if (timeout < 0 || timeout > 1000) {
                timeout = 1000;
        }

	if (!active[0]) {
		err = poll(&fds[1], 1, timeout);
	} if (!active[1]) {
		err = poll(fds, 1, timeout);
	} else {
		err = poll(fds, 2, timeout);
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

        // handle IAC
        parsed_buffer_t pb = parse_iac(from_sock);
        for (std::vector<IACCommand>::iterator itr = pb.first.begin();
             itr != pb.first.end();
             ++itr) {
                uint32_t cookie;
                switch (itr->s.command) {
                case IAC_LITERAL:
                        to_fd.append(1, IAC_LITERAL);
                        break;
                case IAC_ECHO_REQUEST:
                        cookie = htonl(itr->s.commands.echo_cookie);
                        logger->debug("Got echo request %u", cookie);
                        to_sock += iac_echo_reply(cookie);
                        break;
                case IAC_ECHO_REPLY:
                        cookie = htonl(itr->s.commands.echo_cookie);
                        logger->debug("Got echo reply %u", cookie);
                        break;
                case IAC_WINDOW_SIZE:
                        struct winsize ws;
                        ws.ws_col = ntohs(itr->s.commands.window_size.cols);
                        ws.ws_row = ntohs(itr->s.commands.window_size.rows);
                        if (0 > ioctl(fd.get(), TIOCSWINSZ, &ws)) {
                                THROW(Err::ErrSys, "ioctl(TIOCSWINSZ)");
                        }
                        break;
                default:
                        THROW(Err::ErrBase, "Invalid IAC!");
                }
        }

        // add user data to output queue
        to_fd += pb.second;

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
        logger->debug("sslproc::user_loop");
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

        // main loop
	for (;;) {
                try {
                        if (connect_fd_sock(terminal,
                                            sock,
                                            to_client,
                                            from_sock,
                                            to_terminal)) {
                                break;
                        }
                } catch(const FDWrap::ErrEOF &e) {
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
 * If login(3) exists then it'll take a struct utmp, so use that. Else assume
 * that there's a utmpx and use pututxline() (utmp) and updwtmpx() (wtmp)
 *
 * Run as: root
 */
void
log_login(const struct passwd *pw, const std::string &peer_addr)
{
#ifdef HAVE_LOGIN
        struct utmp ut;
        struct timeval tv;
        memset(&ut, 0, sizeof(ut));
#ifdef HAVE_UTMP_TYPE
        ut.ut_type = USER_PROCESS;
#endif
#ifdef HAVE_UTMP_PID
        ut.ut_pid = getpid();
#endif
        strncpy(ut.ut_line,
                short_ttyname.c_str(),
                sizeof(ut.ut_line) - 1);
#ifdef HAVE_UTMP_ID
        strncpy(ut.ut_id,
                short2_ttyname.c_str(),
                sizeof(ut.ut_id) - 1);
#endif

#ifdef HAVE_UTMP_TIME
        ut.ut_time = time(0);
#endif

#ifdef HAVE_UTMP_TV
        gettimeofday(&tv, NULL);
        ut.ut_tv.tv_sec = tv.tv_sec;
        ut.ut_tv.tv_usec = tv.tv_usec;
#endif

        strncpy(ut.ut_name,
                pw->pw_name,
                sizeof(ut.ut_name) - 1);
        strncpy(ut.ut_host,
                peer_addr.c_str(),
                sizeof(ut.ut_host) - 1);
        //ut.ut_addr = 0;
        login(&ut);

#else /* HAVE_LOGIN */
        struct utmpx ut;
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
                //ut.ut_addr = 0;
        }
        if (1) {
                setutent();
                if (!pututxline(&ut)) {
                        THROW(Err::ErrSys, "pututxline()");
                }
                endutent();
        }

        // write to wtmp file (last -10)
        if (1) {
                updwtmpx(WTMPX_FILE, &ut);
        }
#endif
}

/**
 * Write logout info to wtmp
 *
 *
 * @todo This is not pretty. I feel like it at least needs locking.
 *       What I'd really like is a updwtmp() that uses FILE* or int fd.
 *       This racy way is how OpenBSD does it though.
 *
 * Linux and OpenBSD have struct utmp, so use that. Solaris cleans up after
 * logged out users, so maybe we don't need to do anything.
 *
 * Run as: logged in user. The fd of wtmp was opened before chroot()
 *         and dropping privs
 */
void
log_logout()
{
#if HAVE_UTMP_H
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
        logger->debug("sslproc::spawn_child");

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
 * 1) verify client cert information
 * 2) start up tlsshd_shellproc
 * 3) run I/O loop for whole session
 * 4) shut down session
 *
 * At this point the cert is guaranteed to be signed by the ClientCA.
 * We now check who the client subject is.
 *
 * @param[in,out] sock   SSL socket. Handshake complete, ready to use.
 */
void
new_ssl_connection(SSLSocket &sock)
{
        logger->debug("tlsshd-ssl::new_ssl_connection()");
	std::auto_ptr<X509Wrap> cert = sock.get_cert();
	if (!cert.get()) {
		sock.full_write("You are the no-cert client. Goodbye.");
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

/** SIGINT handler for tlssh-sslproc
 *
 * only the listener gets killed by pkill -INT tlsshd, not existing
 * connections.
 *
 * @todo Find a clean way to always log a message here
 */
void
sigint(int)
{
        /* ignore SIGINT */
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
        logger->debug("tlsshd-ssl:forkmain()");
	try {
                if (SIG_ERR == signal(SIGINT, sigint)) {
                        THROW(Err::ErrBase, "signal(SIGINT, sigint)");
                }

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
