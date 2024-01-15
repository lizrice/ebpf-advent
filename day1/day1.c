#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "day1.h"
#include "day1.skel.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static bool keepRunning = true;

void intHandler(int) {
    keepRunning = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	struct tm *tm;
	char ts[32];
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-6d %-8s %-16s %-6d\n",
	       ts, e.pid, e.task, e.filename, e.result);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

void filter_executable(struct day1_bpf *skel, const char *exe) {
	struct executable_t e = {};
	memset(&e, 0, sizeof(e));
	__u32 val = 1;
	strncpy((char *)&e.name, exe, strlen(exe));
	bpf_map__update_elem(skel->maps.executables, &e, sizeof(e), &val, sizeof(val), 0);
	printf("filtered %s\n", exe);
}

void filter_filename(struct day1_bpf *skel, const char *filename) {
	struct filename_t f; 
	memset(&f, 0, sizeof(f));
	__u32 val = 1;
	strncpy((char *)&f.name, filename, strlen(filename));
	bpf_map__update_elem(skel->maps.filenames, &f, sizeof(f), &val, sizeof(val), 0);
	printf("filtered %s\n", filename);
}

#ifdef PART2A
#define ADD_ENTRY(ss, ii, nn, oo) si.state=ss;si.input=ii;so.new_state=nn;so.output=oo; \
	bpf_map__update_elem(skel->maps.state_table, &si, sizeof(si), &so, sizeof(so), 0);


//          e  i  g  h  t  o  n  r  w  f  u  v  s  x
// 0        1           7  5  22       12       17
// 1 e      1  2
// 2 ei           3
// 3 eig             4
// 4 eigh               *8 
//                       /7 
// 5 o                     5  6
// 6 on     *1 23
//           /1
// 7 t               8  7            11
// 8 th                          9
// 9 thr    10
//10 thre   *3 2 
//           /1
//11 tw                    *2
//                          /5 
//12 f         15          13          12
//13 fo                        6           14
//14 fou                         *4
//15 fi                                      15  
//16 fiv    *5
//           /1
//17 s      19 18                                 17
//18 si                                             *6
//19 se        2                             20
//20 sev    21
//21 seve      2              *7
//                             /22
//22 n         23             22
//23 ni                       24
//24 nin    *9 23
//           /1                 

// Additionally if the new state is 0, we need to run through the table again to
// account for the input being the first character of a number
void populate_state_table(struct day1_bpf *skel) {
	struct state_input si = {};
	struct state_output so = {}; 

	ADD_ENTRY(0, 'e', 1, 0);
	ADD_ENTRY(0, 't', 7, 0);
	ADD_ENTRY(0, 'o', 5, 0);
	ADD_ENTRY(0, 'n', 22, 0);
	ADD_ENTRY(0, 'f', 12, 0);
	ADD_ENTRY(0, 's', 17, 0);

	ADD_ENTRY(1, 'e', 1, 0);
	ADD_ENTRY(1, 'i', 2, 0);
	ADD_ENTRY(2, 'g', 3, 0);
	ADD_ENTRY(3, 'h', 4, 0);
	ADD_ENTRY(4, 't', 7, 8);

	ADD_ENTRY(5, 'o', 5, 0);
	ADD_ENTRY(5, 'n', 6, 0);
	ADD_ENTRY(6, 'e', 1, 1);
	ADD_ENTRY(6, 'i', 23, 0);

	ADD_ENTRY(7, '7', 7, 0);
	ADD_ENTRY(7, 'h', 8, 0);
	ADD_ENTRY(7, 'w', 11, 0);
	ADD_ENTRY(8, 'r', 9, 0);
	ADD_ENTRY(9, 'e', 10, 0);
	ADD_ENTRY(10, 'e', 1, 3);
	ADD_ENTRY(10, 'i', 2, 0);
	ADD_ENTRY(11, 'o', 5, 2);

	ADD_ENTRY(12, 'i', 15, 0);
	ADD_ENTRY(12, 'o', 13, 0);
	ADD_ENTRY(12, 'f', 12, 0);

	ADD_ENTRY(13, 'n', 6, 0);
	ADD_ENTRY(13, 'u', 14, 0);
	ADD_ENTRY(14, 'r', 0, 4);
	ADD_ENTRY(15, 'v', 16, 0);
	ADD_ENTRY(16, 'e', 1, 5);

	ADD_ENTRY(17, 'e', 19, 0);
	ADD_ENTRY(17, 'i', 18, 0);
	ADD_ENTRY(17, 's', 17, 0);

	ADD_ENTRY(18, 'x', 0, 6);
	ADD_ENTRY(19, 'i', 2, 0);
	ADD_ENTRY(19, 'v', 20, 0);
	ADD_ENTRY(20, 'e', 21, 0);
	ADD_ENTRY(21, 'n', 22, 7);
	ADD_ENTRY(21, 'i', 2, 0);

	ADD_ENTRY(22, 'i', 23, 0);
	ADD_ENTRY(22, 'n', 22, 0);
	ADD_ENTRY(23, 'n', 24, 0);
	ADD_ENTRY(24, 'e', 1, 9);
	ADD_ENTRY(24, 'i', 23, 0);
}
#endif

int main()
{
    struct day1_bpf *skel;
	struct perf_buffer *pb = NULL;

    int err = 0;

	struct sigaction act;
    act.sa_handler = intHandler;
    sigaction(SIGINT, &act, NULL);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	skel = day1_bpf__open_opts(&opts);
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = day1_bpf__load(skel);
	// Print the verifier log
	for (int i=0; i < sizeof(log_buf); i++) {
		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
			break;
		}
		printf("%c", log_buf[i]);
	}

	if (err) {
		printf("Failed to load BPF object\n");
		day1_bpf__destroy(skel);
		return 1;
	}

	// Define the executables & files we are interested in
	filter_executable(skel, "cat");
	filter_filename(skel, "advent");
	filter_filename(skel, "advent.full");
	filter_filename(skel, "advent.example");
	filter_filename(skel, "advent.test");

#ifdef PART2A
	printf("Populated state table\n");
	populate_state_table(skel);
#endif

	printf("%-8s %-6s %-8s %-16s %-6s\n", "TIME", "PID", "COMM", "FILE", "RESULT");

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
			      handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}
	
	// Attach the progam to the event
	err = day1_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		day1_bpf__destroy(skel);
        return 1;
	}


	while (keepRunning) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;		
	}

cleanup:
	perf_buffer__free(pb);
	day1_bpf__destroy(skel);
	return -err;
}



