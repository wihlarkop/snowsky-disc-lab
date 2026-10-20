#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

static const char success_output[] = "SNOWSKY_MIPS32LE_EXECUTION_OK\n";
static const char failure_output[] = "SNOWSKY_MIPS32LE_EXPECTED_FAILURE\n";

/* First-party filesystem probe. These are synthetic paths, never a stock rootfs. */
static int filesystem_probe(void) {
    static const char marker[] = "SNOWSKY_SYNTHETIC_ROOTFS_V1\n";
    static const char private_data[] = "SNOWSKY_PRIVATE_SESSION_V1\n";
    static const char results[] =
        "input_read=ok\nreadonly_write_errno=30\nprivate_create_read=ok\n"
        "temporary_create_read=ok\noutside_write_errno=30\n"
        "host_path_errno=2\nfresh_session=ok\n";
    char buffer[128];
    int fd = open("/synthetic-rootfs/etc/lab-marker", O_RDONLY);
    if (fd < 0 || read(fd, buffer, sizeof(buffer)) != (ssize_t)(sizeof(marker) - 1) ||
        memcmp(buffer, marker, sizeof(marker) - 1) != 0 || close(fd) != 0) return 40;
    errno = 0;
    fd = open("/synthetic-rootfs/etc/lab-marker", O_WRONLY | O_TRUNC);
    if (fd >= 0 || errno != EROFS) return 41;
    /* O_EXCL also demonstrates fresh state when a second session runs this probe. */
    fd = open("/session-data/probe", O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, private_data, sizeof(private_data) - 1) !=
        (ssize_t)(sizeof(private_data) - 1) || lseek(fd, 0, SEEK_SET) != 0 ||
        read(fd, buffer, sizeof(buffer)) != (ssize_t)(sizeof(private_data) - 1) ||
        memcmp(buffer, private_data, sizeof(private_data) - 1) != 0 || close(fd) != 0)
        return 42;
    fd = open("/session-tmp/probe", O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, marker, sizeof(marker) - 1) != (ssize_t)(sizeof(marker) - 1) ||
        lseek(fd, 0, SEEK_SET) != 0 ||
        read(fd, buffer, sizeof(buffer)) != (ssize_t)(sizeof(marker) - 1) ||
        memcmp(buffer, marker, sizeof(marker) - 1) != 0 || close(fd) != 0) return 43;
    errno = 0;
    fd = open("/outside-synthetic-contract", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0 || errno != EROFS) return 44;
    errno = 0;
    fd = open("/host-private-marker", O_RDONLY);
    if (fd >= 0 || errno != ENOENT) return 45;
    if (write(STDOUT_FILENO, results, sizeof(results) - 1) !=
        (ssize_t)(sizeof(results) - 1)) return 46;
    return 0;
}

int main(int argc, char **argv) {
    if (getpid() <= 0) {
        return 90;
    }

    if (argc == 2 && strcmp(argv[1], "--filesystem") == 0) return filesystem_probe();

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
