// -*- c++ -*-
// tlssh/src/tlssh.cc

#define BEGIN_NAMESPACE(a) namespace a {
#define END_NAMESPACE(a) }
#define BEGIN_LOCAL_NAMESPACE() namespace {
#define END_LOCAL_NAMESPACE() }

#include"fdwrap.h"
#include"errbase.h"

BEGIN_NAMESPACE(tlssh_common);
typedef union {
        struct {
                uint8_t iac;
                uint8_t command;
                union {
                        struct {
                                uint16_t cols;
                                uint16_t rows;
                        } ws;
                        char terminal[32];
                } commands;
        } s;
        char buf[];
} IACCommand;

END_NAMESPACE(tlssh_common);

BEGIN_NAMESPACE(tlsshd);
struct Options {
	std::string port;
	std::string certfile;
	std::string keyfile;
	std::string clientcafile;
	std::string clientcapath;
	std::string config;
	std::string cipher_list;
	std::string tcp_md5;
	std::string chroot;
        int verbose;
        bool daemon;
};
extern Options options;
extern std::string protocol_version;

END_NAMESPACE(tlsshd);


BEGIN_NAMESPACE(tlsshd_shellproc);
int forkmain(const struct passwd *pw, int fd_control);
END_NAMESPACE(tlsshd_shellproc);

BEGIN_NAMESPACE(tlsshd_sslproc);
int forkmain(FDWrap&fd);
END_NAMESPACE(tlsshd_sslproc);


/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
