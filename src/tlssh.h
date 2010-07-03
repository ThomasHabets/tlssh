#define BEGIN_NAMESPACE(a) namespace a {
#define END_NAMESPACE(a) }
#define BEGIN_LOCAL_NAMESPACE() namespace {
#define END_LOCAL_NAMESPACE() }

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
                } commands;
        } s;
        char buf[];
} IACCommand;
END_NAMESPACE(tlssh_common);


/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
