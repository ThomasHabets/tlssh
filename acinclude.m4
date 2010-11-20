AC_DEFUN([EL_GETPW_R_POSIX],
[
   AC_MSG_CHECKING([whether getpwnam_r and getpwuid_r are posix like])
      # The prototype for the POSIX version is:
      # int getpwnam_r(char *, struct passwd *, char *, size_t, struct passwd **)
      # int getpwuid_r(uid_t, struct passwd *, char *, size_t, struct passwd **);
   AC_TRY_LINK([#include <stdlib.h>
                #include <sys/types.h>
                #include <pwd.h>],
               [getpwnam_r(NULL, NULL, NULL, (size_t)0, NULL);
                getpwuid_r((uid_t)0, NULL, NULL, (size_t)0, NULL);],
      [AC_DEFINE([HAVE_GETPW_R_POSIX], 1, [Define to 1 if you have getpwnam_r and getpwuid_r that are POSIX.1 compatible.]) 
       AC_MSG_RESULT(yes)],
      [AC_MSG_RESULT(no)])
])

AC_DEFUN([EL_GETPW_R_DRAFT],
[
   AC_MSG_CHECKING([whether getpwnam_r and getpwuid_r are posix _draft_ like])
      # The prototype for the POSIX draft version is:
      # struct passwd *getpwuid_r(uid_t, struct passwd *, char *, int);
      # struct passwd *getpwnam_r(char *, struct passwd *,  char *, int);
   AC_TRY_LINK([#include <stdlib.h>
                #include <sys/types.h>
                #include <pwd.h>],
               [getpwnam_r(NULL, NULL, NULL, (size_t)0);
                getpwuid_r((uid_t)0, NULL, NULL, (size_t)0);],
      [AC_DEFINE([HAVE_GETPW_R_DRAFT], 1, [Define to 1 if you have getpwnam_r and getpwuid_r that are draft POSIX.1 versions.])
       AC_MSG_RESULT(yes)],
      [AC_MSG_RESULT(no)])
])

# check for clock_gettime(CLOCK_MONOTONIC, ...)
AC_DEFUN([EL_CLOCK_MONOTONIC],
[
    AC_SEARCH_LIBS([clock_gettime], [rt])
    AC_CACHE_CHECK([for CLOCK_MONOTONIC],
                   ac_cv_have_clock_monotonic,
                   [
                     AC_TRY_RUN(
                                [
#include <time.h>
int main() {
struct timespec ts;
exit(!!clock_gettime(CLOCK_MONOTONIC, &ts));
}
                                ],
                        [ ac_cv_have_clock_monotonic="yes"],
                        [ ac_cv_have_clock_monotonic="no" ]
                          )
])
AM_CONDITIONAL(HAVE_CLOCK_MONOTONIC, test x$ac_cv_have_clock_monotonic = xyes)
if test x$ac_cv_have_clock_monotonic = xyes; then
   AC_DEFINE([HAVE_CLOCK_MONOTONIC], 1, [Have symbol CLOCK_MONOTONIC])
fi
])

