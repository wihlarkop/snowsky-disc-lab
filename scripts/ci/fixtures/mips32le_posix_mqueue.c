#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define QUEUE_NAME "/snowsky_disc_lab_mqueue_probe_v1"
#define QUEUE_MAX_MESSAGES 2
#define QUEUE_MESSAGE_BYTES 64
#define MESSAGE_PRIORITY 7U
#define PAYLOAD_SHA256 "b8e0b0e98d2906e4b1d5cdaf72e10f44468760938a4c004c85fcbb7a4160e206"

static const char payload[] = "SNOWSKY_MIPS32LE_POSIX_MQ_V1";
static mqd_t active_queue = (mqd_t)-1;
static int queue_is_owned;
static int keep_queue_linked;

static const char *errno_label(int value) {
    switch (value) {
        case 0: return "NONE";
        case EACCES: return "EACCES";
        case EAGAIN: return "EAGAIN";
        case EBADF: return "EBADF";
        case EEXIST: return "EEXIST";
        case EINTR: return "EINTR";
        case EINVAL: return "EINVAL";
        case EMFILE: return "EMFILE";
        case ENFILE: return "ENFILE";
        case ENOENT: return "ENOENT";
        case ENOMEM: return "ENOMEM";
        case ENOSPC: return "ENOSPC";
        case ENOSYS: return "ENOSYS";
        case EPERM: return "EPERM";
        default: return "OTHER";
    }
}

static int fail_probe(const char *stage, int error_number) {
    printf("MQ_ERROR_STAGE=%s\nMQ_ERROR_NAME=%s\nMQ_ERROR_ERRNO=%d\n",
           stage, errno_label(error_number), error_number);
    fflush(stdout);
    if (active_queue != (mqd_t)-1) {
        (void)mq_close(active_queue);
        active_queue = (mqd_t)-1;
    }
    if (queue_is_owned && !keep_queue_linked) {
        (void)mq_unlink(QUEUE_NAME);
        queue_is_owned = 0;
    }
    return 40;
}

static int verify_attributes(mqd_t descriptor, const char *label) {
    struct mq_attr attributes;
    struct stat metadata;
    if (mq_getattr(descriptor, &attributes) != 0) {
        return fail_probe("mq_getattr", errno);
    }
    if (attributes.mq_maxmsg != QUEUE_MAX_MESSAGES ||
        attributes.mq_msgsize != QUEUE_MESSAGE_BYTES || attributes.mq_curmsgs != 0 ||
        attributes.mq_flags != O_NONBLOCK) {
        return fail_probe("attributes", 0);
    }
    if (fstat((int)descriptor, &metadata) != 0) {
        return fail_probe("fstat_mode", errno);
    }
    if ((metadata.st_mode & 0777) != 0600) {
        return fail_probe("mode", 0);
    }
    printf("%s=maxmsg:%ld,msgsize:%ld,curmsgs:%ld,nonblock:true\n",
           label, attributes.mq_maxmsg, attributes.mq_msgsize,
           attributes.mq_curmsgs);
    printf("%s_MODE=0600\n", label);
    return 0;
}

static int expect_unlinked(void) {
    errno = 0;
    mqd_t missing = mq_open(QUEUE_NAME, O_RDONLY | O_NONBLOCK);
    if (missing != (mqd_t)-1) {
        (void)mq_close(missing);
        return fail_probe("reopen_after_unlink", 0);
    }
    if (errno != ENOENT) {
        return fail_probe("reopen_after_unlink", errno);
    }
    printf("REOPEN_AFTER_UNLINK=ENOENT:2\n");
    return 0;
}

static int open_exclusive(struct mq_attr *requested, const char *label) {
    active_queue = mq_open(QUEUE_NAME,
                           O_CREAT | O_EXCL | O_NONBLOCK | O_RDWR,
                           0600, requested);
    if (active_queue == (mqd_t)-1) {
        return fail_probe("exclusive_create", errno);
    }
    queue_is_owned = 1;
    printf("%s=ok\n", label);
    return 0;
}

static int first_session(struct mq_attr *requested) {
    printf("QUEUE_PROBE=first\nQUEUE_NAME=%s\n", QUEUE_NAME);
    if (open_exclusive(requested, "CREATE") != 0 ||
        verify_attributes(active_queue, "ATTRIBUTES") != 0) {
        return 40;
    }

    errno = 0;
    mqd_t duplicate = mq_open(QUEUE_NAME,
                              O_CREAT | O_EXCL | O_NONBLOCK | O_RDWR,
                              0600, requested);
    if (duplicate != (mqd_t)-1) {
        (void)mq_close(duplicate);
        return fail_probe("duplicate_exclusive_create", 0);
    }
    if (errno != EEXIST) {
        return fail_probe("duplicate_exclusive_create", errno);
    }
    printf("DUPLICATE_CREATE=EEXIST:17\n");

    if (mq_send(active_queue, payload, sizeof(payload) - 1,
                MESSAGE_PRIORITY) != 0) {
        return fail_probe("mq_send", errno);
    }
    printf("SEND=ok\n");

    char received[QUEUE_MESSAGE_BYTES];
    unsigned int priority = 0;
    errno = 0;
    ssize_t length = mq_receive(active_queue, received, sizeof(received), &priority);
    if (length != (ssize_t)(sizeof(payload) - 1) ||
        memcmp(received, payload, sizeof(payload) - 1) != 0 ||
        priority != MESSAGE_PRIORITY) {
        return fail_probe("mq_receive_verify", errno);
    }
    printf("RECEIVE=ok\nPAYLOAD_BYTES=%u\nPAYLOAD_SHA256=%s\nPRIORITY=%u\n",
           (unsigned int)length, PAYLOAD_SHA256, priority);

    if (mq_close(active_queue) != 0) {
        return fail_probe("mq_close_initial", errno);
    }
    active_queue = (mqd_t)-1;
    printf("CLOSE=ok\n");
    if (mq_unlink(QUEUE_NAME) != 0) {
        return fail_probe("mq_unlink_initial", errno);
    }
    queue_is_owned = 0;
    printf("UNLINK=ok\n");
    if (expect_unlinked() != 0) {
        return 40;
    }

    if (open_exclusive(requested, "RECREATE") != 0 ||
        verify_attributes(active_queue, "RETAINED_ATTRIBUTES") != 0) {
        return 40;
    }
    if (mq_close(active_queue) != 0) {
        return fail_probe("mq_close_retained", errno);
    }
    active_queue = (mqd_t)-1;
    keep_queue_linked = 1;
    printf("RETAINED_CLOSE=ok\nQUEUE_LINKED_AT_EXIT=yes\n");
    return 0;
}

static int second_session(struct mq_attr *requested) {
    printf("QUEUE_PROBE=second\nQUEUE_NAME=%s\n", QUEUE_NAME);
    if (open_exclusive(requested, "CREATE") != 0 ||
        verify_attributes(active_queue, "ATTRIBUTES") != 0) {
        return 40;
    }
    if (mq_close(active_queue) != 0) {
        return fail_probe("mq_close_second", errno);
    }
    active_queue = (mqd_t)-1;
    printf("CLOSE=ok\n");
    if (mq_unlink(QUEUE_NAME) != 0) {
        return fail_probe("mq_unlink_second", errno);
    }
    queue_is_owned = 0;
    printf("UNLINK=ok\n");
    return expect_unlinked();
}

int main(int argc, char **argv) {
    struct mq_attr requested = {
        .mq_flags = 0,
        .mq_maxmsg = QUEUE_MAX_MESSAGES,
        .mq_msgsize = QUEUE_MESSAGE_BYTES,
        .mq_curmsgs = 0,
    };

    umask(0077);
    if (argc != 2) {
        return fail_probe("fixed_argument", 0);
    }
    if (strcmp(argv[1], "first") == 0) {
        return first_session(&requested);
    }
    if (strcmp(argv[1], "second") == 0) {
        return second_session(&requested);
    }
    return fail_probe("fixed_argument", 0);
}
