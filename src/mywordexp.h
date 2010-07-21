#ifdef HAVE_WORDEXP_H
#include<wordexp.h>
#else
#include<inttypes.h>
typedef struct {
  size_t we_wordc;
  char **we_wordv;
  size_t we_offs;
} wordexp_t;
extern "C" {
int wordexp(const char *s, wordexp_t *p, int flags);
void wordfree(wordexp_t *p);
};
#endif
