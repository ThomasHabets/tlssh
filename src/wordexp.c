/**
 * @file src/wordexp.c
 * minimal wordexp() implementation for OSs that don't have it
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_WORDEXP
#include<stdio.h>
#include<stdlib.h>
#include<sys/syslimits.h>
#include"mywordexp.h"

/** Mimimal wordexp() implementation that only handles "~"
 *
 * @param[in]  s     String to process
 * @param[out] w     List of hits, caller frees using wordfree()
 * @param[in] flags  Not implemented in this hack
 *
 * @return 0 on success
 */
int
wordexp(const char *s, wordexp_t *w, int flags)
{
  char home[PATH_MAX + 1];
  const char *thome = getenv("HOME");
  if (!thome) {
    return -1;
  }
  if (strlcpy(home, thome, sizeof(home)) >= sizeof(home)) {
    return -1;
  }

  // count number of "~"
  int homedirs = 0;
  int slen = 0;
  const char *p;
  for (p = s; *p; p++) {
    if (*p == '~') {
      homedirs++;
    }
    slen++;
  }
  w->we_wordv = malloc(sizeof(char*));
  if (!w->we_wordv) {
    return -1;
  }
  slen += homedirs * strlen(home);
  w->we_wordv[0] = malloc(slen + 1);
  if (!w->we_wordv[0]) {
    free(w->we_wordv);
    return -1;
  }
  w->we_wordc = 1;
  for (p = s; *p; p++) {
    if (*p == '~') {
      strcat(w->we_wordv[0], home);
    } else {
      char *t;
      t = index(w->we_wordv[0], 0);
      *t++ = *p;
      *t = 0;
    }
  }
  return 0;
}

/** free() a wordexp() result
 *
 */
void
wordfree(wordexp_t *p)
{
  size_t n;
  for (n = 0; n < p->we_wordc; n++) {
    free(p->we_wordv[n]);
  }
  free(p->we_wordv);
}

}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

#endif
