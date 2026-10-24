#include <signal.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include "signals.h"

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig) {
	(void)sig;
	running = 0;
}

int signals_init(void) {
	struct sigaction sa = {
	    .sa_handler = handle_signal,
	};

	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) < 0)
		return -errno;

	if (sigaction(SIGTERM, &sa, NULL) < 0)
		return -errno;

	return 0;
}

int signals_running(void) { return running != 0; }
