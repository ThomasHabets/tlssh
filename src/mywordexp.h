/**
 * @file src/mywordexp.h
 * wordexp.h implementation for OSs that don't have it.
 */
#ifdef HAVE_WORDEXP_H
#include<wordexp.h>
#else
#include<inttypes.h>
typedef struct {
  size_t we_wordc;
  char **we_wordv;
  size_t we_offs;
} wordexp_t;

#ifdef __cplusplus
extern "C" {
#endif

int wordexp(const char *s, wordexp_t *p, int flags);
void wordfree(wordexp_t *p);

#ifdef __cplusplus
};
#endif

#endif
