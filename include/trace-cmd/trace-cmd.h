/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _TRACE_CMD_H
#define _TRACE_CMD_H

#include "event-parse.h"
#include "tracefs.h"

struct tracecmd_input;

enum tracecmd_open_flags {
	TRACECMD_FL_LOAD_NO_PLUGINS		= 1 << 0, /* Do not load plugins */
	TRACECMD_FL_LOAD_NO_SYSTEM_PLUGINS	= 1 << 1, /* Do not load system plugins */
};
struct tracecmd_input *tracecmd_open_head(const char *file, int flags);
struct tracecmd_input *tracecmd_open(const char *file, int flags);
struct tracecmd_input *tracecmd_open_fd(int fd, int flags);

void tracecmd_close(struct tracecmd_input *handle);

int tracecmd_init_data(struct tracecmd_input *handle);
struct tep_record *
tracecmd_read_cpu_first(struct tracecmd_input *handle, int cpu);
struct tep_record *
tracecmd_read_data(struct tracecmd_input *handle, int cpu);
struct tep_record *
tracecmd_read_at(struct tracecmd_input *handle, unsigned long long offset,
		 int *cpu);
void tracecmd_free_record(struct tep_record *record);

struct tep_handle *tracecmd_get_tep(struct tracecmd_input *handle);
unsigned long long tracecmd_get_traceid(struct tracecmd_input *handle);
int tracecmd_get_guest_cpumap(struct tracecmd_input *handle,
			      unsigned long long trace_id,
			      const char **name,
			      int *vcpu_count, const int **cpu_pid);
unsigned long long tracecmd_get_first_ts(struct tracecmd_input *handle);
void tracecmd_add_ts_offset(struct tracecmd_input *handle, long long offset);
int tracecmd_buffer_instances(struct tracecmd_input *handle);
const char *tracecmd_buffer_instance_name(struct tracecmd_input *handle, int indx);
struct tracecmd_input *tracecmd_buffer_instance_handle(struct tracecmd_input *handle, int indx);

void tracecmd_set_loglevel(enum tep_loglevel level);


// Don't use these! These ids are machine-dependent
#define WAKEUP_ID 316
#define WAKEUP_NEW_ID 315
#define SWITCH_ID 314
#define EXIT_ID 311

struct recorder_data;

#include <sys/types.h>

struct rbftrace_event_raw {
	unsigned short 	id;
	unsigned long long 	ts;

	/* Common fields. If sched_switch, this information refers to the prev process */
	pid_t 	pid;
	int 	prio;

	/* sched_switch only */
	long 	prev_state; // Current state of the previous process
	pid_t 	next_pid;
	int 	next_prio;

	/* sched_wakeup only*/
	int 	success;
	int 	target_cpu;
};

/* Record */
struct recorder_data *rbftrace_create_recorders(struct tracefs_instance *tracefs, int cpu_cnt);
int rbftrace_create_recorder(int cpu, int *event_pipe, char *tracefs_path);
void rbftrace_stop_threads(struct recorder_data *recorders, int cpu_cnt);
void rbftrace_wait_threads(struct recorder_data *recorders, int cpu_cnt);

/* Stream */
int rbftrace_parse_event(struct tep_event *source, struct rbftrace_event_raw *target, struct tep_record *record);
struct tracecmd_input *rbftrace_init_stream(int read_fd, int cpu, int cpu_cnt);
int rbftrace_read_stream(struct recorder_data *recorders, int cpu_cnt, struct rbftrace_event_raw *rbf_event);
void rbftrace_print_event(struct rbftrace_event_raw *event);

#endif /* _TRACE_CMD_H */
