#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_WORDEXP
#include<stdio.h>
#include<stdlib.h>
#include<sys/syslimits.h>
#include"wordexp.h"

/**
 * Mimimal wordexp() implementation that only handles "~"
 */
int
wordexp(const char *s, wordexp_t *w, int flags)
{
  char home[PATH_MAX + 1];
  if (strlcpy(home, getenv("HOME"), sizeof(home)) > PATH_MAX) {
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


void
wordfree(wordexp_t *p)
{
  size_t n;
  for (n = 0; n < p->we_wordc; n++) {
    free(p->we_wordv[n]);
  }
  free(p->we_wordv);
}


#endif
