/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <sched.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/errno.h>
#include <Availability.h>

#include "iot_debug.h"
#include "iot_error.h"
#include "iot_os_util.h"
#include "iot_bsp_random.h"

const unsigned int iot_os_max_delay = 0xFFFFFFFF;
const unsigned int iot_os_true = true;
const unsigned int iot_os_false = false;

const char* iot_os_get_os_name()
{
       return "DARWIN";
}

#define _STR_HELPER(x) #x
#define _STR(x) _STR_HELPER(x)
const char* iot_os_get_os_version_string()
{
#ifdef __MAC_OS_X_VERSION_MAX_ALLOWED
       return _STR(__MAC_OS_X_VERSION_MAX_ALLOWED);
#else
       return "";
#endif
}

/* Thread */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	pthread_t* thread = malloc(sizeof(pthread_t));
	pthread_attr_t attr;

	if (thread == NULL)
		return IOT_ERROR_MEM_ALLOC;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_create(thread, &attr, thread_function, data);

	pthread_attr_destroy(&attr);

	if (thread_handle != NULL) {
		*thread_handle = (iot_os_thread*)thread;
	}

	return IOT_OS_TRUE;
}

void iot_os_thread_delete(iot_os_thread thread_handle)
{
	if (thread_handle != NULL) {
		pthread_t* thread = (pthread_t*)thread_handle;
		pthread_cancel(*thread);
		free(thread);
	} else {
		pthread_cancel(pthread_self());
	}
}

void iot_os_thread_yield()
{
	sched_yield();
}

int iot_os_thread_get_current_handle(iot_os_thread* thread_handle)
{
    if (thread_handle == NULL) {
        return IOT_OS_FALSE;
    }

    *thread_handle = (iot_os_thread)pthread_self();
    return IOT_OS_TRUE;
}

/* Queue */
typedef struct {
	int item_size;
	int pipes[2];
} iot_os_queue_posix_t;

iot_os_queue* iot_os_queue_create(int queue_length, int item_size)
{
	iot_os_queue_posix_t* queue = malloc(sizeof(iot_os_queue_posix_t));

	if (queue == NULL) {
		return NULL;
	}

	if (pipe(queue->pipes) < 0) {
		free(queue);
		return NULL;
	}
	queue->item_size = item_size;
	fcntl(queue->pipes[0], F_SETFL, O_NONBLOCK);
	fcntl(queue->pipes[1], F_SETFL, O_NONBLOCK);

	return (void*)queue;
}

int iot_os_queue_reset(iot_os_queue* queue_handle)
{
	iot_os_queue_posix_t* queue = (iot_os_queue_posix_t*)queue_handle;
	char *buf = malloc(queue->item_size);

	// drain the pipe
	while (read(queue->pipes[0], buf, sizeof(*buf)) > 0);
	free(buf);

	return IOT_OS_TRUE;
}

void iot_os_queue_delete(iot_os_queue* queue_handle)
{
	iot_os_queue_posix_t* queue = (iot_os_queue_posix_t*)queue_handle;

	close(queue->pipes[0]);
	close(queue->pipes[1]);
	free(queue);
}

int iot_os_queue_send(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	iot_os_queue_posix_t* queue = (iot_os_queue_posix_t*)queue_handle;
	struct pollfd fds;
	int rc, nwrote = 0;;

	if (!queue || !data) {
	    return IOT_OS_FALSE;
	}

	fds.fd = queue->pipes[1];
	fds.events = POLLOUT;

	do {
		rc = poll(&fds, 1, wait_time_ms);
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				// poll failed
				break;
			}
		} else if (rc == 0) {
			// timeout
			break;
		} else if (fds.revents & POLLOUT) {
			// TODO: read in a loop and update timeout
			nwrote = write(queue->pipes[1], data, queue->item_size);
			break;
		} else if (fds.revents & (POLLERR | POLLNVAL)) {
			break;
		}
	} while(1);

	if (nwrote != queue->item_size) {
		return IOT_OS_FALSE;
	}
	return IOT_OS_TRUE;
}

int iot_os_queue_receive(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	iot_os_queue_posix_t* queue = (iot_os_queue_posix_t*)queue_handle;
	struct pollfd fds;
	int rc, nread = 0;

	fds.fd = queue->pipes[0];
	fds.events = POLLIN;

	do {
		rc = poll(&fds, 1, wait_time_ms);
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				// poll failed
				break;
			}
		} else if (rc == 0) {
			// timeout
			break;
		} else if (fds.revents & POLLIN) {
			// TODO: read in a loop and update timeout
			nread = read(queue->pipes[0], data, queue->item_size);
			break;
		} else if (fds.revents & (POLLERR | POLLNVAL)) {
			break;
		}
	} while(1);

	if (nread != queue->item_size) {
		return IOT_OS_FALSE;
	}
	return IOT_OS_TRUE;
}

/* Event Group */

#define EVENT_MAX 8

typedef struct {
	unsigned char id;
	int fd[2];
} event_t;

typedef struct {
	event_t group[EVENT_MAX];
	unsigned char event_status;
} eventgroup_t;

iot_os_eventgroup* iot_os_eventgroup_create(void)
{
	eventgroup_t *eventgroup = malloc(sizeof(eventgroup_t));
	if (eventgroup == NULL)
		return NULL;

	for (int i = 0; i < EVENT_MAX; i++) {
		eventgroup->group[i].id = (1 << i);
		int ret = pipe(eventgroup->group[i].fd);
		if (ret == -1) {
			free(eventgroup);
			return NULL;
		}
	}
	eventgroup->event_status = 0;

	return eventgroup;
}

void iot_os_eventgroup_delete(iot_os_eventgroup* eventgroup_handle)
{
	eventgroup_t* eventgroup = eventgroup_handle;

	for (int i = 0; i < EVENT_MAX; i++) {
		close(eventgroup->group[i].fd[0]);
		close(eventgroup->group[i].fd[1]);
	}

	free(eventgroup);
}

unsigned char iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_wait_for, const int clear_on_exit, const unsigned int wait_time_ms)
{
	eventgroup_t *eventgroup = eventgroup_handle;
	fd_set readfds;
	int fd_max = 0;
	unsigned char event_status_backup;

	FD_ZERO(&readfds);

	for (int i = 0; i < EVENT_MAX; i++) {
		if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_wait_for)) {
			FD_SET(eventgroup->group[i].fd[0], &readfds);
			if (eventgroup->group[i].fd[0] >= fd_max) {
				fd_max = eventgroup->group[i].fd[0];
			}
		}
	}

	char buf[3] = {0,};
	struct timeval tv;
	memset(&tv, 0x00, sizeof(tv));
	unsigned char bits = 0x00;
	ssize_t read_size = 0;

	tv.tv_sec = wait_time_ms / 1000;
	tv.tv_usec = (wait_time_ms % 1000) * 1000;

	int ret = select(fd_max + 1, &readfds, NULL, NULL, &tv);
	if (ret == -1) {
		// Select Error
		return 0;
	} else if (ret == 0) {
		// Select Timeout
		return (unsigned int)eventgroup->event_status;
	} else {
		// read pipe
		for (int i = 0; i < EVENT_MAX; i++) {
			if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_wait_for)) {
				if (FD_ISSET(eventgroup->group[i].fd[0], &readfds)) {
					memset(buf, 0, sizeof(buf));
					read_size = read(eventgroup->group[i].fd[0], buf, sizeof(buf));
					IOT_DEBUG("read_size = %d", read_size);
					bits |= eventgroup->group[i].id;
				}
			}
		}

		event_status_backup = eventgroup->event_status;
		if (clear_on_exit) {
			eventgroup->event_status &= ~(bits);
		}

		return (unsigned int)event_status_backup;
	}
}

int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_set)
{
	eventgroup_t *eventgroup = eventgroup_handle;
	unsigned char bits = 0;
	ssize_t write_size = 0;

	for (int i = 0; i < EVENT_MAX; i++) {
        if (eventgroup->group[i].id == (eventgroup->group[i].id & eventgroup->event_status)) {
            IOT_DEBUG("already set 0x08x", eventgroup->group[i].id);
            continue;
        }
		if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_set)) {
			write_size = write(eventgroup->group[i].fd[1], "Set", strlen("Set"));
			IOT_DEBUG("write_size = %d", write_size);
			bits |= eventgroup->group[i].id;
		}
	}

	eventgroup->event_status |= bits;

	return IOT_OS_TRUE;
}

int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_clear)
{
    eventgroup_t *eventgroup = eventgroup_handle;

    eventgroup->event_status &= ~(bits_to_clear);
    // TODO: clear written event to pipe

	return IOT_OS_TRUE;
}

/* Mutex */

int iot_os_mutex_init(iot_os_mutex* mutex)
{
	if (!mutex) {
		return IOT_OS_FALSE;
	}

	pthread_mutex_t* mutex_p = malloc(sizeof(pthread_mutex_t));
	if (!mutex_p) {
		return IOT_OS_FALSE;
	} else {
		pthread_mutex_init(mutex_p, NULL);
		mutex->sem = mutex_p;
	}
	return IOT_OS_TRUE;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	if (!mutex || !mutex->sem) {
		return IOT_OS_FALSE;
	}

	pthread_mutex_t* mutex_p = mutex->sem;

	pthread_mutex_lock(mutex_p);

	return IOT_OS_TRUE;
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	if (!mutex || !mutex->sem) {
		return IOT_OS_FALSE;
	}

	pthread_mutex_t* mutex_p = mutex->sem;

	pthread_mutex_unlock(mutex_p);

	return IOT_OS_TRUE;
}

void iot_os_mutex_destroy(iot_os_mutex* mutex)
{
	if (!mutex || !mutex->sem) {
		return;
	}
	pthread_mutex_t* mutex_p = mutex->sem;

	pthread_mutex_destroy(mutex_p);
}

/* Delay */
void iot_os_delay(unsigned int delay_ms)
{
	struct timespec ts = {0,};

	ts.tv_sec = delay_ms / 1000;
	ts.tv_nsec = (delay_ms % 1000) * 1000000;

	nanosleep(&ts, NULL);
}

/* Timer */
typedef struct itimerspec {
	struct timespec it_interval;  /* Timer interval */
	struct timespec it_value;     /* Initial expiration */
};

typedef struct {
	struct itimerspec it;
	struct timespec ts;
} mach_timer_t;

void mach_gettime(mach_timer_t *mt, struct itimerspec *it)
{
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);
	// ignore it_interval for now as it is unused
	it->it_interval.tv_sec = 0;
	it->it_interval.tv_nsec = 0;
	// TODO: deal with negative values
	it->it_value.tv_sec = now.tv_sec - mt->ts.tv_sec + mt->it.it_value.tv_sec;
	it->it_value.tv_nsec = now.tv_nsec - mt->ts.tv_nsec + mt->it.it_value.tv_nsec;
}

void mach_settime(mach_timer_t *mt, struct itimerspec *it)
{
	mt->it.it_interval.tv_sec = it->it_interval.tv_sec;
	mt->it.it_interval.tv_nsec = it->it_interval.tv_nsec;
	mt->it.it_value.tv_sec = it->it_value.tv_sec;
	mt->it.it_value.tv_nsec = it->it_value.tv_nsec;
	clock_gettime(CLOCK_REALTIME, &(mt->ts));
}

void iot_os_timer_count_ms(iot_os_timer timer, unsigned int timeout_ms)
{
	mach_timer_t *mt = (mach_timer_t *)&timer;
	struct itimerspec it;

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_nsec = 0;
	it.it_value.tv_sec = timeout_ms / 1000;
	it.it_value.tv_nsec = (timeout_ms % 1000) * 1000000;
	mach_settime(mt, &it);
}

unsigned int iot_os_timer_left_ms(iot_os_timer timer)
{
	mach_timer_t *mt = (mach_timer_t *)&timer;
	struct itimerspec it = {0,};

	mach_gettime(mt, &it);
	return (it.it_value.tv_sec * 1000) + (it.it_value.tv_nsec / 1000000);
}

char iot_os_timer_isexpired(iot_os_timer timer)
{
	mach_timer_t *mt = (mach_timer_t *)&timer;
	struct itimerspec it = {0,};

	mach_gettime(mt, &it);

	if (it.it_value.tv_sec == 0 && it.it_value.tv_nsec == 0) {
		return IOT_OS_TRUE;
	} else {
		return IOT_OS_FALSE;
	}
}

int iot_os_timer_init(iot_os_timer *timer)
{
	mach_timer_t *mt = malloc(sizeof(mach_timer_t));

	if (mt == NULL) {
		return IOT_ERROR_MEM_ALLOC;
	}

	*timer = mt;
	return IOT_ERROR_NONE;
}

void iot_os_timer_destroy(iot_os_timer *timer)
{
	mach_timer_t *mt = (mach_timer_t *)timer;

	free(mt);
}

/* Memory */
void *iot_os_malloc(size_t size)
{
    return malloc(size);
}

void *iot_os_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

char *iot_os_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void iot_os_free(void *ptr)
{
    return free(ptr);
}

char *iot_os_strdup(const char *src)
{
    return strdup(src);
}
