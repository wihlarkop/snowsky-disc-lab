/* First-party firmware-free UI contract fixture. No vendor code or assets.
 * RGBA8888, 16x8, tightly packed; a bright cursor moves one pixel on RIGHT.
 * Only fixed tmpfs paths, a hex session token, and reviewed modes are accepted.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int frame(const char *path, int cursor) {
    unsigned char rgba[16 * 8 * 4];
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 16; ++x) {
            int i = (y * 16 + x) * 4;
            rgba[i] = x == cursor ? 240 : 16;
            rgba[i + 1] = x == cursor ? 192 : 32;
            rgba[i + 2] = x == cursor ? 32 : 48;
            rgba[i + 3] = 255;
        }
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return errno == EEXIST ? 45 : 46;
    ssize_t n = write(fd, rgba, sizeof rgba);
    int closed = close(fd);
    return n == sizeof rgba && closed == 0 ? 0 : 46;
}
int main(int argc, char **argv) {
    if (argc != 3 || strlen(argv[1]) != 32 ||
        strspn(argv[1], "0123456789abcdef") != 32 ||
        (strcmp(argv[2], "normal") && strcmp(argv[2], "early"))) return 47;
    if (!strcmp(argv[2], "early")) return 43;
    int status = frame("/session-data/initial.rgba", 2);
    if (status) return status;
    printf("READY %s\n", argv[1]);
    fflush(stdout);
    struct pollfd p = {STDIN_FILENO, POLLIN, 0};
    if (poll(&p, 1, 1000) != 1) return 42;
    char event[32] = {0};
    ssize_t n = read(STDIN_FILENO, event, sizeof event);
    if (n != 6 || memcmp(event, "RIGHT\n", 6)) return 41;
    status = frame("/session-data/changed.rgba", 3);
    if (status) return status;
    printf("MOVED %s\n", argv[1]);
    return fflush(stdout) ? 46 : 0;
}
