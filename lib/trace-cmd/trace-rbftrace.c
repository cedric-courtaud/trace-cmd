#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "trace-cmd-private.h"


/* Data of recorder threads */
struct recorder_data {
	int			pid;
	int			event_pipe[2];
	int			cpu;
	int			closed;
	struct tracecmd_input	*stream;
	struct tep_record	*record;
};

// Used by each child recorder after forking. Each child has its own "recorder" instance
static struct tracecmd_recorder *recorder;
static int sleep_time = 1000;
// If true, the thread must stop (could be the main thread or a child recorder)
static int finished = 0;

static void finish() {
	if (recorder)
		tracecmd_stop_recording(recorder); // Only executed by child recorders
	finished = 1;
}

void rbftrace_stop_threads(struct recorder_data *recorders, int cpu_cnt) {
	int i;
	// int ret;
	// struct rbftrace_event_raw *event = malloc(sizeof(*event));

	/* Tell all threads to finish up */
	for (i = 0; i < cpu_cnt; i++) {
		if (recorders[i].pid > 0) {
			kill(recorders[i].pid, SIGUSR1);
		}
	}

	/* Flush out the pipes */
	/* Edit: we do this from rust in the event generator */
	// do {
	// 	ret = read_stream(recorders, cpu_cnt, event);
	// 	printf("Flushed: ");
	// 	print_event(event);
	// } while (ret > 0);

	// free(event);
}

void rbftrace_wait_threads(struct recorder_data *recorders, int cpu_cnt) {
	int i;

	for (i = 0; i < cpu_cnt; i++) {
		if (recorders[i].pid > 0) {
			waitpid(recorders[i].pid, NULL, 0);
			recorders[i].pid = -1;
			fprintf(stderr, "Waited recorder #%d\n", i);
		}
	}
}

/* Returns recorder pid */
// TODO shall we set real-time priority? In that case, we might need to use add_filter_pid
int rbftrace_create_recorder(int cpu, int *event_pipe, char *tracefs_path) {
	pid_t pid;

	pid = fork();
	// Father
	if (pid != 0)
		return pid;

	// Child
	signal(SIGINT, SIG_IGN); // Ignore sigint
	signal(SIGUSR1, finish); // Stop on sigusr

	close(event_pipe[0]);
	recorder = tracecmd_create_buffer_recorder_fd(event_pipe[1], cpu, TRACECMD_RECORD_BLOCK_SPLICE, tracefs_path);
	tracefs_put_tracing_file(tracefs_path);
	if (!recorder) {
		printf("Can't create recorder\n");
		exit(-1);
	}

	while (!finished) {
		if (tracecmd_start_recording(recorder, sleep_time) < 0)
			break;
	}
	tracecmd_free_recorder(recorder);
	recorder = NULL;

	exit(0);
}

/* Create recorders: one for each cpu */
struct recorder_data *rbftrace_create_recorders(struct tracefs_instance *tracefs, int cpu_cnt) {
	struct recorder_data *recorders = calloc(cpu_cnt, sizeof(*recorders));
	char *tracefs_path = tracefs_instance_get_dir(tracefs);
	int *event_pipe = NULL;
	int ret;

	for (int i = 0; i < cpu_cnt; i++) {

		/* Setup recorder */
		recorders[i].cpu = i;
		recorders[i].record = NULL;
		event_pipe = recorders[i].event_pipe;
		ret = pipe(event_pipe);
		if (ret < 0) {
			printf("Pipe error\n");
			free(recorders);
			return NULL;
		}
		recorders[i].stream = rbftrace_init_stream(event_pipe[0], i, cpu_cnt);
		if (!recorders[i].stream) {
			printf("Stream error\n");
			free(recorders);
			return NULL;
		}
		fflush(stdout);

		/* Start recorder thread */
		ret = rbftrace_create_recorder(i, event_pipe, tracefs_path);
		recorders[i].pid = ret;
		if (ret < 0) {
			printf("Fork error\n");
			free(recorders);
			return NULL;
		}
        
		if (event_pipe)
			close(event_pipe[1]);
	}

    return recorders;
}

struct tracecmd_input *rbftrace_init_stream(int read_fd, int cpu, int cpu_cnt) {
	struct tracecmd_output *trace_output;
	static struct tracecmd_input *trace_input;
	static FILE *fp = NULL;
	int fd1;
	int fd2;
	long flags;

	if (fp && trace_input)
		goto make_pipe;

	// Create temporary file
	fp = tmpfile();
	if (!fp)
		return NULL;
	fd1 = fileno(fp);
	fd2 = dup(fd1);

	// Write tracecmd binary header in the file to pretend that we are reading from a valid trace.dat file
	trace_output = tracecmd_create_init_fd(fd2);
	if (!trace_output) {
		fclose(fp);
		return NULL;
	}
	tracecmd_output_free(trace_output);

	lseek(fd2, 0, SEEK_SET);

	// Get handle for event stream. This function will check that the fd corresponds to a valid trace.dat file
	trace_input = tracecmd_alloc_fd(fd2, 0);
	if (!trace_input) {
		close(fd2);
		goto fail;
	}

	// Consume binary header
	if (tracecmd_read_headers(trace_input, TRACECMD_FILE_PRINTK) < 0)
		goto fail_free_input;

make_pipe:
	/* Do not block on this pipe */
	flags = fcntl(read_fd, F_GETFL);
	fcntl(read_fd, F_SETFL, flags | O_NONBLOCK);

	if (tracecmd_make_pipe(trace_input, cpu, read_fd, cpu_cnt) < 0)
		goto fail_free_input;

	return trace_input;

fail_free_input:
	tracecmd_close(trace_input);
fail:
	fclose(fp);

	return NULL;
}

/* Read a single event, parse it into "rbf_event" in our format */
/* Returns 1 if an event was read, 0 otherwise (e.g. there were no events to read) */
int rbftrace_read_stream(struct recorder_data *recorders, int cpu_cnt, struct rbftrace_event_raw *rbf_event) {
	struct tep_record *record;
	struct recorder_data *rec;
	struct recorder_data *last_rec;
	struct tep_handle *event_parser;
	struct tep_event *event;
	struct timeval tv = { 1 , 0 };
	fd_set rfds;
	int top_rfd = 0;
	int nr_fd;
	int ret;
	int i;

	last_rec = NULL;

	/* Reads a record for each recorder thread */
 again:
	for (i = 0; i < cpu_cnt; i++) {
		rec = &recorders[i];

		if (!rec->record)
			rec->record = tracecmd_read_data(rec->stream, rec->cpu);
		record = rec->record;
		/* Pipe has closed */
		if (!record && errno == EINVAL)
			rec->closed = 1;

		/* Picks the smallest timestamp */
		if (record && (!last_rec || record->ts < last_rec->record->ts))
			last_rec = rec;
	}
	/* Find the event */
	if (last_rec) {
		record = last_rec->record;
		last_rec->record = NULL;

		event_parser = tracecmd_get_tep(last_rec->stream);
		/* Most recent event. The most recent timestamp is stored in the record. */
		event = tep_find_event_by_record(event_parser, record);

		if (rbf_event != NULL) {
			if (rbftrace_parse_event(event, rbf_event, record) < 0) {
				printf("Parser error: field not found\n");
			}
		}

		tracecmd_free_record(record);

		return 1;
	}

	nr_fd = 0;
	FD_ZERO(&rfds);

	for (i = 0; i < cpu_cnt; i++) {
		/* Do not process closed pipes */
		if (recorders[i].closed)
			continue;
		nr_fd++;
		if (recorders[i].event_pipe[0] > top_rfd)
			top_rfd = recorders[i].event_pipe[0];

		FD_SET(recorders[i].event_pipe[0], &rfds);
	}

	if (!nr_fd)
		return 0;

	ret = select(top_rfd + 1, &rfds, NULL, NULL, &tv);

	if (ret > 0)
		goto again;

	return ret;
}

/* prev_state mapping
0 => R
1 => S
2 => D
...
16 => X
32 => Z
256 => R+ (The flag at 256 seems to trigger the "+")

{ 0x0000, "R" }, 
{ 0x0001, "S" }, 
{ 0x0002, "D" }, 
{ 0x0004, "T" }, 
{ 0x0008, "t" }, 
{ 0x0010, "X" }, 
{ 0x0020, "Z" },
{ 0x0040, "P" }, 
{ 0x0080, "I" }
*/

int rbftrace_parse_event(struct tep_event *source, struct rbftrace_event_raw *target, struct tep_record *record) {
	unsigned long long val;
	bool is_switch = false;

	target->ts = record->ts;
	if (tep_get_common_field_val(NULL, source, "common_type", record, &val, 0) < 0) {
		printf("Field common_type not found\n");
		return -1;
	}
	target->id = val;

	// Depends if it's a wakeup/exit event or a switch event
	if (tep_get_field_val(NULL, source, "prev_pid", record, &val, 0) == 0) {
		is_switch = true;
		target->pid = val;
	} else if (tep_get_field_val(NULL, source, "pid", record, &val, 0) == 0) {
		target->pid = val;
	} else {
		printf("Field pid or prev_pid not found\n");
		return -1;
	}

	if (is_switch) {

		if (tep_get_field_val(NULL, source, "prev_prio", record, &val, 0) < 0) {
			printf("Field prev_prio not found\n");
			return -1;
		}
		target->prio = val;
		if (tep_get_field_val(NULL, source, "prev_state", record, &val, 0) < 0) {
			printf("Field prev_state not found\n");
			return -1;
		}
		target->prev_state = val;
		if (tep_get_field_val(NULL, source, "next_pid", record, &val, 0) < 0) {
			printf("Field next_pid not found\n");
			return -1;
		}
		target->next_pid = val;
		if (tep_get_field_val(NULL, source, "next_prio", record, &val, 0) < 0) {
			printf("Field next_prio not found\n");
			return -1;
		}
		target->next_prio = val;
		
	} else {

		// Shared by sched_wakeup and sched_switch
		if (tep_get_field_val(NULL, source, "prio", record, &val, 0) < 0) {
			printf("Field prio not found\n");
			return -1;
		}
		target->prio = val;

		// These fields are for sched_wakeup only
		if (tep_get_field_val(NULL, source, "success", record, &val, 0) == 0) {
			target->success = val;
			if (tep_get_field_val(NULL, source, "target_cpu", record, &val, 0) < 0) {
				printf("Field target_cpu not found\n");
				return -1;
			}
			target->target_cpu = val;
		}

	}

	return 0;
}
