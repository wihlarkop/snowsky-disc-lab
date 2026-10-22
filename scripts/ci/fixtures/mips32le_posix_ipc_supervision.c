#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char request_payload[] = "SNOWSKY_SUPERVISION_REQUEST_V1";
static const char acknowledgment_payload[] = "SNOWSKY_SUPERVISION_ACK_V1";

static void announce(const char *role, const char *event, const char *queue_state) {
    printf("SYNTHETIC_SUPERVISION_ROLE=%s\n", role);
    printf("SYNTHETIC_SUPERVISION_EVENT=%s\n", event);
    printf("SYNTHETIC_SUPERVISION_QUEUE=%s\n", queue_state);
    fflush(stdout);
}

static void pause_briefly(void) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000};
    nanosleep(&delay, NULL);
}

static void wait_forever(void) {
    for (;;) {
        sleep(1);
    }
}

static void busy_forever(void) {
    volatile unsigned long counter = 0;
    for (;;) {
        counter++;
    }
}

static void queue_names(const char *scenario, const char **request, const char **ack) {
    if (strcmp(scenario, "consumer-exits-before-request") == 0) {
        *request = "/snowsky_disc_lab_supervision_consumer_exit_req_v1";
        *ack = "/snowsky_disc_lab_supervision_consumer_exit_ack_v1";
    } else if (strcmp(scenario, "producer-exits-before-ack") == 0) {
        *request = "/snowsky_disc_lab_supervision_producer_exit_req_v1";
        *ack = "/snowsky_disc_lab_supervision_producer_exit_ack_v1";
    } else if (strcmp(scenario, "producer-exceeds-deadline") == 0) {
        *request = "/snowsky_disc_lab_supervision_deadline_req_v1";
        *ack = "/snowsky_disc_lab_supervision_deadline_ack_v1";
    } else {
        *request = "/snowsky_disc_lab_supervision_sibling_req_v1";
        *ack = "/snowsky_disc_lab_supervision_sibling_ack_v1";
    }
}

static int create_pair(const char *request_name, const char *ack_name, mqd_t *request,
                       mqd_t *ack) {
    struct mq_attr attributes = {.mq_flags = 0, .mq_maxmsg = 2, .mq_msgsize = 64,
                                 .mq_curmsgs = 0};
    *request = mq_open(request_name, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0600,
                       &attributes);
    if (*request == (mqd_t)-1) {
        return -1;
    }
    *ack = mq_open(ack_name, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0600,
                   &attributes);
    if (*ack == (mqd_t)-1) {
        return -1;
    }
    return 0;
}

static mqd_t open_until_ready(const char *name) {
    for (;;) {
        mqd_t queue = mq_open(name, O_RDWR | O_NONBLOCK);
        if (queue != (mqd_t)-1) {
            return queue;
        }
        if (errno != ENOENT) {
            return (mqd_t)-1;
        }
        pause_briefly();
    }
}

static int receive_request(mqd_t request) {
    char message[64];
    unsigned priority = 0;
    for (;;) {
        ssize_t count = mq_receive(request, message, sizeof(message), &priority);
        if (count >= 0) {
            return count == (ssize_t)sizeof(request_payload) - 1 &&
                           memcmp(message, request_payload, sizeof(request_payload) - 1) == 0
                       ? 0
                       : -1;
        }
        if (errno != EAGAIN && errno != EINTR) {
            return -1;
        }
        pause_briefly();
    }
}

static int send_request(mqd_t request) {
    return mq_send(request, request_payload, sizeof(request_payload) - 1, 7);
}

static int send_acknowledgment(mqd_t ack) {
    return mq_send(ack, acknowledgment_payload, sizeof(acknowledgment_payload) - 1, 3);
}

static int wait_for_acknowledgment_pending(mqd_t ack) {
    for (int attempt = 0; attempt < 100; attempt++) {
        struct mq_attr attributes;
        if (mq_getattr(ack, &attributes) != 0) {
            return -1;
        }
        if (attributes.mq_curmsgs > 0) {
            return 0;
        }
        pause_briefly();
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "consumer") != 0 && strcmp(argv[1], "producer") != 0)) {
        return 99;
    }
    const char *role = argv[1];
    const char *scenario = argv[2];
    const char *request_name = NULL;
    const char *ack_name = NULL;
    queue_names(scenario, &request_name, &ack_name);

    if (strcmp(scenario, "consumer-exits-before-request") == 0) {
        if (strcmp(role, "consumer") == 0) {
            announce(role, "exit-before-request", "not-attempted");
            return 42;
        }
        mqd_t request, ack;
        if (create_pair(request_name, ack_name, &request, &ack) != 0) {
            return 90;
        }
        announce(role, "wait-request", "created");
        for (;;) {
            char message[64];
            if (mq_receive(request, message, sizeof(message), NULL) >= 0) {
                return 91;
            }
            if (errno != EAGAIN && errno != EINTR) {
                return 92;
            }
            pause_briefly();
        }
    }

    if (strcmp(scenario, "producer-exits-before-ack") == 0) {
        if (strcmp(role, "producer") == 0) {
            mqd_t request, ack;
            if (create_pair(request_name, ack_name, &request, &ack) != 0 ||
                send_request(request) != 0) {
                return 90;
            }
            if (wait_for_acknowledgment_pending(ack) != 0) {
                return 94;
            }
            announce(role, "send-request-exit-with-ack-pending", "created-ack-pending");
            return 43;
        }
        mqd_t request = open_until_ready(request_name);
        mqd_t ack = open_until_ready(ack_name);
        if (request == (mqd_t)-1 || ack == (mqd_t)-1 || receive_request(request) != 0 ||
            send_acknowledgment(ack) != 0) {
            return 91;
        }
        announce(role, "receive-request-send-ack-wait", "opened");
        wait_forever();
    }

    if (strcmp(scenario, "producer-exceeds-deadline") == 0) {
        if (strcmp(role, "producer") == 0) {
            mqd_t request, ack;
            if (create_pair(request_name, ack_name, &request, &ack) != 0 ||
                send_request(request) != 0) {
                return 90;
            }
            announce(role, "request-sent-deadline-loop", "created");
            busy_forever();
        }
        mqd_t request = open_until_ready(request_name);
        mqd_t ack = open_until_ready(ack_name);
        if (request == (mqd_t)-1 || ack == (mqd_t)-1 || receive_request(request) != 0 ||
            send_acknowledgment(ack) != 0) {
            return 91;
        }
        announce(role, "receive-request-send-ack-wait", "opened");
        wait_forever();
    }

    if (strcmp(scenario, "producer-failure-cancels-sibling") == 0) {
        if (strcmp(role, "producer") == 0) {
            announce(role, "exit-before-request", "not-attempted");
            return 44;
        }
        announce(role, "wait-request", "not-created");
        mqd_t request = open_until_ready(request_name);
        return request == (mqd_t)-1 ? 92 : 93;
    }

    return 99;
}
