/* HEADER Testing get_exec_pipes() */

#if !defined(USING_UTIL_FUNCS_MODULE) || !defined(HAVE_EXECV)
printf("1..0 # skip util_funcs or execv() not available\n");
__did_plan = 1;
return 0;
#else
#include <sys/wait.h>
#include <util_funcs.h>

{
    char            output[64] = "";
    size_t          len = 0;
    ssize_t         n;
    int             fdIn, fdOut;
    netsnmp_pid_t   pid;

    if (get_exec_pipes("/bin/echo a  b", &fdIn, &fdOut, &pid)) {
        close(fdOut);
        while (len < sizeof(output) - 1 &&
               (n = read(fdIn, output + len, sizeof(output) - 1 - len)) > 0)
            len += n;
        output[len] = '\0';
        close(fdIn);
        waitpid(pid, NULL, 0);
    }
    OKF(strcmp(output, "a b\n") == 0, ("output %s <> a b", output));
}
#endif
