/// tlssh/src/tlsshd-shell.cc
/**
 * @addtogroup TLSSHD
 * @file src/tlsshd-shell.cc
 * TLSSHD Shell process.
 *
 * None of the code in this file is run as root. It's all run after
 * authentication as the user who logged in.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<pwd.h>
#include<stdlib.h>
#include<sys/types.h>

#include<iostream>
#include<string>
#include<vector>

#include"tlssh.h"
#include"util.h"

using namespace tlssh_common;
using tlsshd::protocol_version;

BEGIN_NAMESPACE(tlsshd_shellproc);

/**
 *
 */
void
parse_header_line(const std::string &s)
{
        std::vector<std::string> toks(tokenize(s));

        if (toks[0] == "version" && toks.size() == 2) {
                if (toks[1] == "tlssh.1") {
                        protocol_version = toks[1];
                } else {
                        THROW(Err::ErrBase, "incompatible protocol version");
                }
        } else if (toks[0] == "env" && toks.size() == 3) {
                if (setenv(toks[1].c_str(), toks[2].c_str(), 1)) {
                        THROW(Err::ErrBase, "setenv() error");
                }
        } else {
                THROW(Err::ErrBase, "protocol header error");
        }
}


/**
 *
 */
void
forkmain2(const struct passwd *pw, int fd_control)
{
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

        FDWrap fdin(fd_control);
        std::string line;
        for(;;) {
                std::string ch;
                ch = fdin.read(1);
                if (ch == "\r") {
                        ;
                } else if (ch == "\n") {
                        if (line.empty()) {
                                break;
                        } else {
                                parse_header_line(line);
                                line = "";
                        }
                } else {
                        line += ch;
                }
        }


        if (protocol_version.empty()) {
                THROW(Err::ErrBase, "client did not provide protocol version");
        }

	execl(pw->pw_shell, pw->pw_shell, "-i", NULL);

        // while the below works, it requires root and I want to drop
        // root privs before this
        if (0) {
                execl("/bin/login", "/bin/login",
                      "-f", pw->pw_name,
                      "-h", "127.1.2.3",
                      NULL);
        }

        // Should never be reached
	perror("execl() fail");
	exit(1);
}

/**
 * newly fork()ed child that has the new pty as terminal.
 * wrapper function with exception handler
 */
int
forkmain(const struct passwd *pw, int fd_control)
{
        try {
                forkmain2(pw, fd_control);
		return 0;
        } catch (const char *e) {
                logger->err("forkmain_child(): char*: %s", e);
        } catch (const std::exception &e) {
                logger->err("forkmain_child(): std::exception: %s", e.what());
        } catch (...) {
                logger->err("forkmain_child(): Unknown exception caught");
        }
	return 1;
}

END_NAMESPACE(tlsshd_shellproc);
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
