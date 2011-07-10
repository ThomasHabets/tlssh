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
#include<fstream>

#include"tlssh.h"
#include"util2.h"

using namespace tlssh_common;
using tlsshd::protocol_version;

BEGIN_LOCAL_NAMESPACE();
std::string remote_command;
bool use_terminal = true;
END_LOCAL_NAMESPACE();

BEGIN_NAMESPACE(tlsshd_shellproc);

/** Check /etc/shells for a binary and return true if it's there
 *
 */
bool
shell_in_etc_shells(const std::string &sh)
{
        std::ifstream fi("/etc/shells");

        // if file doesn't exist, all shells are OK
        if (!fi.is_open()) {
                return true;
        }

        std::string line;
        while(fi.good()) {
                getline(fi, line);
                if (line == sh) {
                        return true;
                }
        }
        return false;
}

/** Parse protocol header line where client gives some environment
 *  variables like TERM
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
        } else if (toks[0] == "terminal" && toks.size() == 2) {
                if (toks[1] == "off") {
                        use_terminal = false;
                }
        } else if (toks[0] == "command" && toks.size() == 2) {
                remote_command = toks[1];
        } else {
                THROW(Err::ErrBase, "protocol header error: " + s);
        }
}


/** exception-wrapped main function of shell process. Processes
 *  protocol header and spawns shell.
 *
 * @param[in] fd_control   control socket that header data will arrive on
 */
void
forkmain2(const struct passwd *pw, int fd_control)
{
        logger->debug("shellproc(%d)::forkmain2()", getpid());
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

        logger->debug("shellproc(%d)::forkmain2() reading headers", getpid());
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
        fdin.close();

        logger->debug("shellproc(%d)::forkmain2() done reading headers",
                      getpid());

        if (protocol_version.empty()) {
                THROW(Err::ErrBase, "client did not provide protocol version");
        }

        if (!shell_in_etc_shells(pw->pw_shell)) {
                logger->warning("shellproc(%d)::forkmain2(): "
                                "shell not in /etc/shells: <%s>", getpid(),
                                pw->pw_shell);
                THROW(Err::ErrBase, "user shell is not in /etc/shells");
        }

        logger->debug("shellproc(%d)::forkmain2(): spawning shell <%s>",
                      getpid(),
                      pw->pw_shell);

        std::string shellbase = gnustyle_basename(pw->pw_shell);
        if (remote_command.empty()) {
                execl(pw->pw_shell, ("-" + shellbase).c_str(), NULL);
        } else {
                logger->debug("shellproc(%d)::forkmain2: remote command: <%s>",
                              getpid(), remote_command.c_str());
                delete logger;
                execl(pw->pw_shell,
                      shellbase.c_str(),
                      "-c",
                      remote_command.c_str(),
                      NULL);
       }

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
