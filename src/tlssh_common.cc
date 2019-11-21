/**
 * @file src/tlssh_common.cc
 * TLSSH-specific functions common to client and daemon
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>

#include"tlssh.h"

BEGIN_NAMESPACE(tlssh_common)

const int iac_len[256] = {
        2, // reserved
        6, // IAC_WINDOW_SIZE   (struct {uint16 cols,rows})
        6, // IAC_ECHO_REQUEST  (uint32 echo_cookie)
        6, // IAC_ECHO_REPLY    (uint32 echo_cookie)
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2,  // IAC_LITERAL
};

/** Generate IAC sequence for echo request
 *
 */
std::string
iac_echo_request(uint32_t cookie)
{
        logger->debug("Generating IAC echo request %u", cookie);
        IACCommand cmd;
        cmd.s.iac = IAC_LITERAL;
        cmd.s.command = IAC_ECHO_REQUEST;
        cmd.s.commands.echo_cookie = htonl(cookie);
        return std::string(&cmd.buf[0],
                           &cmd.buf[iac_len[IAC_ECHO_REQUEST]]);
}

/** Generate IAC sequence for echo request
 *
 */
std::string
iac_echo_reply(uint32_t cookie)
{
        logger->debug("Generating IAC echo reply %u", cookie);
        IACCommand cmd;
        cmd.s.iac = IAC_LITERAL;
        cmd.s.command = IAC_ECHO_REPLY;
        cmd.s.commands.echo_cookie = htonl(cookie);
        return std::string(&cmd.buf[0],
                           &cmd.buf[iac_len[IAC_ECHO_REPLY]]);
}

/**
 * Run as: user, in both server and client
 *
 * All plaintext from socket is filtered through this function in
 * order to extract any IAC (Interpret As Command) stuff.
 *
 * 'buffer' contains data from the socket (after SSL has decrypted
 * it).
 *
 * User data and IAC will be returned. Either one can be empty. Caller *must*
 * process IACs before processing user data.
 *
 * (A literal IAC could in theory be special-cased as user data, but
 * that isn't being done)
 *
 *
 * @param[in,out] buffer    Raw data we got from socket.
 * @return                  pair of vector<IACCommand> and string
 */
parsed_buffer_t
parse_iac(std::string &buffer)
{
        parsed_buffer_t ret;
        size_t iac_pos;

        const IACCommand *cmd;

        for (;;) {
                if (buffer.empty()) {
                        break;
                }

                iac_pos = buffer.find((char)IAC_LITERAL);

                // fast path: *only* user data in the buffer
                if (iac_pos == std::string::npos) {
                        ret.second += buffer;
                        buffer = "";
                        break;
                }

                // case 1: buffer starts with user data. Extract it and return.
                if (iac_pos > 0) {
                        ret.second += buffer.substr(0, iac_pos);
                        buffer.erase(0, iac_pos);
                        break;
                }

                cmd = reinterpret_cast<const IACCommand*>(buffer.data());

                // case 2: incomplete IAC. Do nothing.
                if (iac_len[cmd->s.command] > buffer.size()) {
                        break;
                }

                // case 3: complete IAC. Handle it and continue eating buffer
                IACCommand iac;
                memcpy(&iac, buffer.data(), iac_len[cmd->s.command]);
                ret.first.push_back(iac);

                buffer.erase(0, iac_len[cmd->s.command]);
        }
        return ret;
}

/** Print version info according to GNU coding standards
 *
 */
void
print_version()
{
        printf("tlssh %s\n"
               "Copyright (C) 2010 Thomas Habets <thomas@habets.se>\n"
               "License 3-clause BSD. Run with --copying to see the whole"
               " license.\n"
               "This is free software: you are free to change and "
               "redistribute it.\n"
               "There is NO WARRANTY, to the extent permitted by law.\n",
               VERSION);
}

/** Print version info according to GNU coding standards
 *
 */
void
print_copying()
{
        printf("tlssh %s\n", VERSION);
        printf("(BSD license without advertising clause below)\n"
               "\n"
               " Copyright (c) 2010 Thomas Habets. All rights reserved.\n"
               "\n"
               " Redistribution and use in source and binary forms, with or "
               "without\n"
               " modification, are permitted provided that the following "
               "conditions\n"
               " are met:\n"
               " 1. Redistributions of source code must retain the above "
               "copyright\n"
               "    notice, this list of conditions and the following "
               "disclaimer.\n"
               " 2. Redistributions in binary form must reproduce the above "
               "copyright\n"
               "    notice, this list of conditions and the following "
               "disclaimer in"
               " the\n"
               "    documentation and/or other materials provided with the "
               "distribution.\n"
               " 3. The name of the author may not be used to endorse or"
               " promote"
               " products\n"
               "    derived from this software without specific prior written "
               "permission.\n"
               "\n"
               " THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY "
               "EXPRESS "
               "OR\n"
               " IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE "
               "IMPLIED "
               "WARRANTIES\n"
               " OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE "
               "DISCLAIMED.\n"
               " IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, "
               "INDIRECT,\n"
               " INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES "
               "(INCLUDING, BUT\n"
               " NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; "
               "LOSS"
               " OF USE,\n"
               " DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED "
               "AND "
               "ON ANY\n"
               " THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT "
               "LIABILITY, OR "
               "TORT\n"
               " (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT "
               "OF THE "
               "USE OF\n"
               " THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH "
               "DAMAGE.\n");
        exit(0);
}

END_NAMESPACE(tlssh_common)

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
