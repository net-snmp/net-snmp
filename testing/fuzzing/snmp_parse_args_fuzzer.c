 /*
  * Copyright (c) 2025, Net-snmp authors
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions are met:
  *
  * * Redistributions of source code must retain the above copyright notice, this
  *   list of conditions and the following disclaimer.
  *
  * * Redistributions in binary form must reproduce the above copyright notice,
  *   this list of conditions and the following disclaimer in the documentation
  *   and/or other materials provided with the distribution.
  *
  * * Neither the name of the copyright holder nor the names of its
  *   contributors may be used to endorse or promote products derived from
  *   this software without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/snmp_parse_args.h>
#include "ada_fuzz_header.h"

int
LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    af_gb_init();

    int argc = (af_get_short(&data, &size) % 99) + 1;
    char **argv = malloc(argc * sizeof(*argv));
    for (int i = 0; i < argc; i++) {
        argv[i] = af_gb_get_null_terminated(&data, &size);
        if (!argv[i])
            goto free_argv;
    }

#if 0
    snmp_set_do_debugging(1);
    debug_register_tokens("snmp_parse_args");
#endif

    netsnmp_session *ss = SNMP_MALLOC_TYPEDEF(netsnmp_session);

    snmp_parse_args(argc, argv, ss, "", NULL);

    snmp_close(ss);
    netsnmp_cleanup_session(ss);
    free(ss);

free_argv:
    free(argv);

    af_gb_cleanup();

    return 0;
}
