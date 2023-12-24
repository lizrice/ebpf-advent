// Inspired by bcc/libbbpf-tools/filelife.h
#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16

struct event {
	char filename[DNAME_INLINE_LEN];
	char task[TASK_COMM_LEN];
   __u32 result;
	pid_t pid;
};

struct executable_t {
   char name[TASK_COMM_LEN];
};

struct filename_t {
   char name[DNAME_INLINE_LEN];
};

struct state_input {
	char state;
	char input;
};

struct state_output {
	char new_state;
	char output;
};

