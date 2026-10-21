#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define REQUEST_QUEUE "/snowsky_disc_lab_handoff_req_v1"
#define ACK_QUEUE "/snowsky_disc_lab_handoff_ack_v1"
#define QUEUE_MAX_MESSAGES 2
#define QUEUE_MESSAGE_BYTES 64
#define REQUEST_PRIORITY 7U
#define ACK_PRIORITY 3U
#define DEADLINE_SECONDS 5

static const char request_payload[] = "SNOWSKY_HANDOFF_REQUEST_V1";
static const char acknowledgment_payload[] = "SNOWSKY_HANDOFF_ACK_V1";

static mqd_t request_descriptor = (mqd_t)-1;
static mqd_t acknowledgment_descriptor = (mqd_t)-1;
static int request_linked;
static int acknowledgment_linked;

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

static void report_error(const char *role, const char *stage, int error_number) {
    printf("HANDOFF_ERROR_ROLE=%s\nHANDOFF_ERROR_STAGE=%s\n"
           "HANDOFF_ERROR_NAME=%s\nHANDOFF_ERROR_ERRNO=%d\n",
           role, stage, errno_label(error_number), error_number);
    fflush(stdout);
}

static int close_descriptor(mqd_t *descriptor, const char *role, const char *stage) {
    if (*descriptor == (mqd_t)-1) {
        return 0;
    }
    if (mq_close(*descriptor) != 0) {
        report_error(role, stage, errno);
        *descriptor = (mqd_t)-1;
        return -1;
    }
    *descriptor = (mqd_t)-1;
    return 0;
}

static int unlink_owned_queues(const char *role) {
    int failed = 0;
    if (request_linked) {
        if (mq_unlink(REQUEST_QUEUE) != 0) {
            report_error(role, "cleanup_unlink_request", errno);
            failed = 1;
        } else {
            request_linked = 0;
        }
    }
    if (acknowledgment_linked) {
        if (mq_unlink(ACK_QUEUE) != 0) {
            report_error(role, "cleanup_unlink_acknowledgment", errno);
            failed = 1;
        } else {
            acknowledgment_linked = 0;
        }
    }
    return failed ? -1 : 0;
}

static int fail_probe(const char *role, const char *stage, int error_number) {
    report_error(role, stage, error_number);
    (void)close_descriptor(&request_descriptor, role, "cleanup_close_request");
    (void)close_descriptor(&acknowledgment_descriptor, role, "cleanup_close_acknowledgment");
    if (strcmp(role, "consumer") == 0) {
        (void)unlink_owned_queues(role);
    }
    return 40;
}

static int deadline_expired(const struct timespec *started) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return now.tv_sec - started->tv_sec >= DEADLINE_SECONDS;
}

static void retry_pause(void) {
    const struct timespec interval = {.tv_sec = 0, .tv_nsec = 1000000};
    (void)nanosleep(&interval, NULL);
}

static int verify_queue(mqd_t descriptor, const char *role, const char *stage) {
    struct mq_attr attributes;
    struct stat metadata;
    if (mq_getattr(descriptor, &attributes) != 0) {
        return fail_probe(role, stage, errno);
    }
    if (attributes.mq_maxmsg != QUEUE_MAX_MESSAGES ||
        attributes.mq_msgsize != QUEUE_MESSAGE_BYTES || attributes.mq_curmsgs != 0) {
        return fail_probe(role, stage, 0);
    }
    if (fstat((int)descriptor, &metadata) != 0) {
        return fail_probe(role, stage, errno);
    }
    if ((metadata.st_mode & 0777) != 0600) {
        return fail_probe(role, stage, 0);
    }
    return 0;
}

static int create_consumer_queues(void) {
    struct mq_attr requested = {
        .mq_flags = 0,
        .mq_maxmsg = QUEUE_MAX_MESSAGES,
        .mq_msgsize = QUEUE_MESSAGE_BYTES,
        .mq_curmsgs = 0,
    };
    request_descriptor = mq_open(
        REQUEST_QUEUE, O_CREAT | O_EXCL | O_NONBLOCK | O_RDWR, 0600, &requested);
    if (request_descriptor == (mqd_t)-1) {
        return fail_probe("consumer", "create_request", errno);
    }
    request_linked = 1;
    acknowledgment_descriptor = mq_open(
        ACK_QUEUE, O_CREAT | O_EXCL | O_NONBLOCK | O_RDWR, 0600, &requested);
    if (acknowledgment_descriptor == (mqd_t)-1) {
        return fail_probe("consumer", "create_acknowledgment", errno);
    }
    acknowledgment_linked = 1;
    if (verify_queue(request_descriptor, "consumer", "request_attributes") != 0 ||
        verify_queue(acknowledgment_descriptor, "consumer", "acknowledgment_attributes") != 0) {
        return 40;
    }
    printf("QUEUE_CREATE_REQUEST=ok\nQUEUE_CREATE_ACK=ok\n"
           "QUEUE_ATTRIBUTES_REQUEST=mode:0600,maxmsg:2,msgsize:64,curmsgs:0\n"
           "QUEUE_ATTRIBUTES_ACK=mode:0600,maxmsg:2,msgsize:64,curmsgs:0\n");
    return 0;
}

static int wait_for_queues(void) {
    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        return fail_probe("producer", "clock_read", errno);
    }
    for (;;) {
        request_descriptor = mq_open(REQUEST_QUEUE, O_WRONLY | O_NONBLOCK);
        if (request_descriptor != (mqd_t)-1) {
            acknowledgment_descriptor = mq_open(ACK_QUEUE, O_RDONLY | O_NONBLOCK);
            if (acknowledgment_descriptor != (mqd_t)-1) {
                break;
            }
            int error_number = errno;
            (void)close_descriptor(
                &request_descriptor, "producer", "cleanup_close_request");
            if (error_number != ENOENT && error_number != EINTR) {
                return fail_probe("producer", "open_acknowledgment", error_number);
            }
        } else if (errno != ENOENT && errno != EINTR) {
            return fail_probe("producer", "open_request", errno);
        }
        int expired = deadline_expired(&started);
        if (expired < 0) {
            return fail_probe("producer", "clock_read", errno);
        }
        if (expired) {
            return fail_probe("producer", "queue_readiness_timeout", ENOENT);
        }
        retry_pause();
    }
    if (verify_queue(request_descriptor, "producer", "request_attributes") != 0 ||
        verify_queue(acknowledgment_descriptor, "producer", "acknowledgment_attributes") != 0) {
        return 40;
    }
    printf("QUEUE_OPEN_REQUEST=ok\nQUEUE_OPEN_ACK=ok\n");
    return 0;
}

static int retry_send(mqd_t descriptor, const char *payload, size_t bytes,
                      unsigned int priority, const char *role, const char *stage) {
    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        return fail_probe(role, "clock_read", errno);
    }
    for (;;) {
        if (mq_send(descriptor, payload, bytes, priority) == 0) {
            return 0;
        }
        if (errno != EAGAIN && errno != EINTR) {
            return fail_probe(role, stage, errno);
        }
        int expired = deadline_expired(&started);
        if (expired < 0) {
            return fail_probe(role, "clock_read", errno);
        }
        if (expired) {
            return fail_probe(role, stage, EAGAIN);
        }
        retry_pause();
    }
}

static int retry_receive(mqd_t descriptor, char *buffer, size_t capacity,
                         const char *role, const char *stage, ssize_t *received,
                         unsigned int *priority) {
    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        return fail_probe(role, "clock_read", errno);
    }
    for (;;) {
        *received = mq_receive(descriptor, buffer, capacity, priority);
        if (*received >= 0) {
            return 0;
        }
        if (errno != EAGAIN && errno != EINTR) {
            return fail_probe(role, stage, errno);
        }
        int expired = deadline_expired(&started);
        if (expired < 0) {
            return fail_probe(role, "clock_read", errno);
        }
        if (expired) {
            return fail_probe(role, stage, EAGAIN);
        }
        retry_pause();
    }
}

static int consumer(void) {
    printf("HANDOFF_ROLE=consumer\n");
    if (create_consumer_queues() != 0) {
        return 40;
    }

    char received[QUEUE_MESSAGE_BYTES];
    unsigned int priority = 0;
    ssize_t length = -1;
    if (retry_receive(request_descriptor, received, sizeof(received), "consumer",
                      "request_timeout", &length, &priority) != 0) {
        return 40;
    }
    if (length != (ssize_t)(sizeof(request_payload) - 1) ||
        memcmp(received, request_payload, sizeof(request_payload) - 1) != 0) {
        return fail_probe("consumer", "request_payload", 0);
    }
    if (priority != REQUEST_PRIORITY) {
        return fail_probe("consumer", "request_priority", 0);
    }
    printf("REQUEST_RECEIVE=ok\nREQUEST_BYTES=%u\n"
           "REQUEST_SHA256=a27944201ce35b61283b9b24f246c935070e81d7f2fc241170c8a47bb9b12354\n"
           "REQUEST_PRIORITY=7\n",
           (unsigned int)length);

    if (retry_send(acknowledgment_descriptor, acknowledgment_payload,
                   sizeof(acknowledgment_payload) - 1, ACK_PRIORITY,
                   "consumer", "acknowledgment_send") != 0) {
        return 40;
    }
    printf("ACK_SEND=ok\n");
    if (close_descriptor(&request_descriptor, "consumer", "close_request") != 0 ||
        close_descriptor(&acknowledgment_descriptor, "consumer", "close_acknowledgment") != 0) {
        return 40;
    }
    printf("QUEUE_CLOSE_REQUEST=ok\nQUEUE_CLOSE_ACK=ok\n");
    if (mq_unlink(REQUEST_QUEUE) != 0) {
        return fail_probe("consumer", "unlink_request", errno);
    }
    request_linked = 0;
    if (mq_unlink(ACK_QUEUE) != 0) {
        return fail_probe("consumer", "unlink_acknowledgment", errno);
    }
    acknowledgment_linked = 0;
    printf("QUEUE_UNLINK_REQUEST=ok\nQUEUE_UNLINK_ACK=ok\n");
    return 0;
}

static int producer(void) {
    printf("HANDOFF_ROLE=producer\n");
    if (wait_for_queues() != 0) {
        return 40;
    }
    if (retry_send(request_descriptor, request_payload, sizeof(request_payload) - 1,
                   REQUEST_PRIORITY, "producer", "request_send") != 0) {
        return 40;
    }
    printf("REQUEST_SEND=ok\n");

    char received[QUEUE_MESSAGE_BYTES];
    unsigned int priority = 0;
    ssize_t length = -1;
    if (retry_receive(acknowledgment_descriptor, received, sizeof(received), "producer",
                      "acknowledgment_timeout", &length, &priority) != 0) {
        return 40;
    }
    if (length != (ssize_t)(sizeof(acknowledgment_payload) - 1) ||
        memcmp(received, acknowledgment_payload, sizeof(acknowledgment_payload) - 1) != 0) {
        return fail_probe("producer", "acknowledgment_payload", 0);
    }
    if (priority != ACK_PRIORITY) {
        return fail_probe("producer", "acknowledgment_priority", 0);
    }
    printf("ACK_RECEIVE=ok\nACK_BYTES=%u\n"
           "ACK_SHA256=35cc983cb77d4d7b5f3f2b489a92d3f5324d131328f354f23fb0a352545dfa7c\n"
           "ACK_PRIORITY=3\n",
           (unsigned int)length);
    if (close_descriptor(&request_descriptor, "producer", "close_request") != 0 ||
        close_descriptor(&acknowledgment_descriptor, "producer", "close_acknowledgment") != 0) {
        return 40;
    }
    printf("QUEUE_CLOSE_REQUEST=ok\nQUEUE_CLOSE_ACK=ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return fail_probe("unknown", "fixed_argument", 0);
    }
    if (strcmp(argv[1], "consumer") == 0) {
        return consumer();
    }
    if (strcmp(argv[1], "producer") == 0) {
        return producer();
    }
    return fail_probe("unknown", "fixed_argument", 0);
}
