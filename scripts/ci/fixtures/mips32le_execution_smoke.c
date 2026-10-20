#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static const char success_output[] = "SNOWSKY_MIPS32LE_EXECUTION_OK\n";
static const char failure_output[] = "SNOWSKY_MIPS32LE_EXPECTED_FAILURE\n";

int main(int argc, char **argv) {
    if (getpid() <= 0) {
        return 90;
    }

    if (argc == 2 && strcmp(argv[1], "--fail") == 0) {
        if (write(STDOUT_FILENO, failure_output, sizeof(failure_output) - 1) !=
            (ssize_t)(sizeof(failure_output) - 1)) {
            return 91;
        }
        return 23;
    }

    if (argc == 2 && strcmp(argv[1], "--timeout") == 0) {
        volatile unsigned long counter = 0;
        for (;;) {
            ++counter;
        }
    }

    if (write(STDOUT_FILENO, success_output, sizeof(success_output) - 1) !=
        (ssize_t)(sizeof(success_output) - 1)) {
        return 92;
    }
    return 0;
}
