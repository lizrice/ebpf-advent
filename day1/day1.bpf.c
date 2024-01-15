#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "day1.h"

#ifdef PART1
#include "day1p1.bpf.c"
#endif
#ifdef PART2
#include "day1p2.bpf.c"
#endif
#ifdef PART2A
#include "day1p2a.bpf.c"
#endif

#define LOOPS 3

struct buffer_t {
   char *buf;
   u16 length;
   u16 offset;
   struct advent_state astate;
   u8 depth;
};

// Maps
// Start event is indexed by pid and stores the event we'll eventually send to
// user space
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct event);
} start_event SEC(".maps");

// Buffer is indexed by pid and holds information about the buffer that the file
// is being read intos
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct buffer_t);
} buffer SEC(".maps");

// Output events
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// Executables we are interested in 
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
	__type(key, struct executable_t);
	__type(value, u32);
} executables SEC(".maps");

// Filenames we are interested in 
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
	__type(key, struct filename_t);
	__type(value, u32);
} filenames SEC(".maps");

// Tail calls
#define DO_BUFFER_READ 0

int buffer_read(struct pt_regs *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));	
	__array(values, int (void *));
} tailcalls SEC(".maps") = {
	.values = {
		[DO_BUFFER_READ] = (void *)&buffer_read, 
	},
};

// When a file is opened, if it's a filename and executable we're interested in,
// create a start_event for this pid
SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, struct path *path, struct file *file)
{
	struct event e = {};
	e.pid = 0;
	e.result = 0; 
	for (u32 i=0; i<TASK_COMM_LEN; i++) {
		e.task[i] = 0;
	}
	for (u32 i=0; i<DNAME_INLINE_LEN; i++) {
		e.filename[i] = 0;
	}

	bpf_get_current_comm(&e.task, sizeof(e.task));
	if (!bpf_map_lookup_elem(&executables, &e.task)) {
		// skip this executable
		return 0;
	}

	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	bpf_probe_read_kernel_str(&e.filename, sizeof(e.filename), &dentry->d_iname);
	if (!bpf_map_lookup_elem(&filenames, &e.filename)) {
		// skip file we're not interested in
		return 0;
	}

	u32 pid = (u32) bpf_get_current_pid_tgid();
	long err = bpf_map_update_elem(&start_event, &pid, &e, 0);
	if (err) {
		bpf_printk("vfs_open: error updating start_event map");
	}

	bpf_printk("vfs_open: file %s found by command %s pid %d", &e.filename, &e.task, pid);
	return 0;
}

// When a file is closed, delete any map entries related to this pid if there
// are any
SEC("kprobe/filp_close")
int BPF_KPROBE(filp_close, struct file *file) 
{
	u32 pid = (u32) bpf_get_current_pid_tgid();
	struct event *e = bpf_map_lookup_elem(&start_event, &pid); 
	if (e) {
		struct buffer_t *b = bpf_map_lookup_elem(&buffer, &pid); 
		if (b) {
			e->result = b->astate.total;
			e->pid = pid;
			bpf_printk("filp_close: total is %d for pid %d, filename %s", e->result, pid, e->filename);
			bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(struct event));
			bpf_map_delete_elem(&buffer, &pid);
		} else {
			bpf_printk("filp_close: missing buffer for pid %d", pid);
		}
		bpf_printk("filp_close: removing start event and buffer for pid %d", pid);
		long err = bpf_map_delete_elem(&start_event, &pid);
		if (err != 0) {
			bpf_printk("filp_close: failed to delete start_event for pid %d", pid);
		}
#ifdef PART2
		err = bpf_map_delete_elem(&digit_state, &pid);
		if (err != 0) {
			bpf_printk("filp_close: failed to delete digit_state for pid %d", pid);
		}
#endif
	} 

	return 0;
}

// When a file is read, check whether it's one we have a start_event for, and if
// we do, initialize an entry in the buffer map. We'll actually look at the
// buffer contents when the read completes using the corresponding kretprobe
SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read, struct file *file, char *buf, size_t count, loff_t *pos)
{
	long err;
	u32 pid = (u32) bpf_get_current_pid_tgid();
	struct event *e = bpf_map_lookup_elem(&start_event, &pid);
	if (!e) {
		// Not a file read we are interested in
		return 0;
	}

	bpf_printk("vfs_read: pid %d, filename %s, task %s", pid, e->filename, e->task);
	struct buffer_t bb = {};
	bb.buf = buf;
	bb.offset = 0;
	bb.length = count; 
	bb.depth = 0;

	struct buffer_t *b;

	b = bpf_map_lookup_elem(&buffer, &pid);
	if (b) {
		bb.astate.first_digit = b->astate.first_digit;
		bb.astate.last_digit = b->astate.last_digit;
		bb.astate.total = b->astate.total;
		bb.astate.lines = b->astate.lines;
	} else {
		bpf_printk("vfs_read: first read for pid %d", pid);
		bb.astate.first_digit = -1;
		bb.astate.last_digit = -1;
		bb.astate.total = 0;
		bb.astate.lines = 0;

#ifdef PART2A		
		bb.astate.table_state = 0;
#endif
#ifdef PART2
		bb.astate.pid = pid;
		struct digit_state_t ds = {}; 
		for (u8 i = 0; i < 10; i++) {
			ds.text_digits[i] = 0;
		}
		err = bpf_map_update_elem(&digit_state, &pid, &ds, 0);
		if (err) {
			bpf_printk("vfs_read: error updating digit_state");
		}
#endif 
	}

	bpf_printk("vfs_read: buf %x with size %d, total so far %d for pid %d", buf, count, bb.astate.total, pid);
	err = bpf_map_update_elem(&buffer, &pid, &bb, 0);
	if (err) {
		bpf_printk("vfs_read: error updating buffer");
	}

   return 0;
}


// Tail call for parsing each character in the buffer
SEC("kprobe")
int buffer_read(struct pt_regs *ctx) {
	u32 pid = (u32) bpf_get_current_pid_tgid();
	struct buffer_t *b = bpf_map_lookup_elem(&buffer, &pid); 
	if (!b) {
		bpf_printk("buffer_read: no buffer state for pid %d", pid);		
		return 0;
	}

	// Can't call bpf_loop with memory from a map, so we need to take a copy 
	struct advent_state astate = {};
	astate.first_digit = b->astate.first_digit;
	astate.last_digit = b->astate.last_digit;
	astate.total = b->astate.total;
	astate.lines = b->astate.lines;
#ifdef PART2A
	astate.table_state = b->astate.table_state;
#endif
#ifdef PART2
	astate.pid = pid;
#endif
	
	char *location;

	for (u8 j = 0; (j < LOOPS) && (b->offset < b->length); j++) {
		location = b->buf + b->offset;
		u32 read_length = b->length - b->offset; 
		if (read_length > ADVENT_BUFFER_LEN) {
			read_length = ADVENT_BUFFER_LEN;
		}
		bpf_printk("buffer_read: length %d, offset %d from %x, read %d chars", b->length, b->offset, b->buf, read_length);
		bpf_probe_read_user(astate.buffer, read_length, location);
		long ii = bpf_loop(read_length, examine_char, &astate, 0);
		if (ii != read_length) {
			bpf_printk("buffer_read: surprise! %d loops != read_length %d");
		}
		b->offset += ADVENT_BUFFER_LEN;
	}

	b->astate.first_digit = astate.first_digit;
	b->astate.last_digit = astate.last_digit;
	b->astate.total = astate.total;
	b->astate.lines = astate.lines;
#ifdef PART2A
	b->astate.table_state = astate.table_state;
#endif
	b->depth = b->depth + 1; 
	bpf_map_update_elem(&buffer, &pid, b, 0);	

	if (b->length > b->offset) {		
		bpf_printk("buffer_read: %d bytes left, total so far is %d, depth %d", b->length - b->offset, b->astate.total, b->depth);
		bpf_tail_call(ctx, &tailcalls, DO_BUFFER_READ);
	}
	return 0;
}

// Some characters have been read into the buffer, so start parsing
SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(vfs_read_ret, long ret)
{
	u32 pid = (u32) bpf_get_current_pid_tgid();

    char task[TASK_COMM_LEN];	
	bpf_get_current_comm(&task, sizeof(task));
	if (!bpf_map_lookup_elem(&executables, &task)) {
		// skip this executable
		// Tracing to try to debug missing kretprobe calls
		// if (pid > 4400) {
		// 	bpf_printk("vfs_read ret: %d", pid);
		// }		
		return 0;
	}

	struct event *e = bpf_map_lookup_elem(&start_event, &pid);
	if (!e) {
		// Not a file read we are interested in
		bpf_printk("vfs_read ret: Not interested for %d", pid);
		return 0;
	}

	struct buffer_t *b = bpf_map_lookup_elem(&buffer, &pid); 
	if (!b) {
		bpf_printk("vfs_read ret: No matching pid entry for %d", pid);
		return 0;
	}

	bpf_printk("vfs_read ret: file read complete %d chars into into %x, total %d for pid %d", ret, b->buf, b->astate.total, pid);
	if (ret <= 0){
		return 0;
	}

	b->depth = 0;    // keeping track of the number of tail calls, because you can only recurse to a depth of 32
	b->length = ret; // number of chars to parse

	bpf_map_update_elem(&buffer, &pid, b, 0);
	bpf_tail_call(ctx, &tailcalls, DO_BUFFER_READ);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
