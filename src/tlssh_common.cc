/**
 * @file src/tlssh_common.cc
 * TLSSH-specific functions common to client and daemon
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<stdio.h>
#include<stdlib.h>

#include"tlssh.h"

BEGIN_NAMESPACE(tlssh_common)
/** Print version info according to GNU coding standards
 *
 */
void
print_version()
{
        printf("tlssh %s\n"
               "Copyright (C) 2010 Thomas Habets <thomas@habets.pp.se>\n"
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
