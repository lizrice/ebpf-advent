#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "day1.h"

// If using examine_char2 we don't have enough stack space so we need a smaller buffer
// #define ADVENT_BUFFER_LEN 300
// For examine_char and examine_char3 we can accommodate a 400 char buffer
#define ADVENT_BUFFER_LEN 400

#define LOOPS 3

// Use examine_char for Part 1
// #define EXAMINE_CHAR examine_char
#define EXAMINE_CHAR examine_char

// Used by examine_char2
// text_digits[1] = 0 if no characters from 'one'
//            [1] = 1 if we found 'o'
//            [1] = 2 if we found 'o' followed by 'n'
struct digit_state_t {
	s8 text_digits[10]; 
};

struct advent_state {
   u16 total;
   u16 lines;
   s8 first_digit;
   s8 last_digit;
   char table_state;
   char buffer[ADVENT_BUFFER_LEN];
   u32 pid;
};

struct buffer_t {
   char *buf;
   u16 length;
   u16 offset;
   struct advent_state astate;
   u8 depth;
};

// Maps
// Start event is indexed by pid
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct event);
} start_event SEC(".maps");

// Buffer is indexed by pid
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct buffer_t);
} buffer SEC(".maps");

// Digit state is indexed by pid (used by examine_char2)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct digit_state_t);
} digit_state SEC(".maps");

// State table is populated in user space
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct state_input);
	__type(value, struct state_output);
} state_table SEC(".maps");

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
		err = bpf_map_delete_elem(&digit_state, &pid);
		if (err != 0) {
			bpf_printk("filp_close: failed to delete digit_state for pid %d", pid);
		}
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
	bb.astate.pid = pid;

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
		bb.astate.pid = pid;
		bb.astate.table_state = 0;
		struct digit_state_t ds = {}; 
		for (u8 i = 0; i < 10; i++) {
			ds.text_digits[i] = 0;
		}
		err = bpf_map_update_elem(&digit_state, &pid, &ds, 0);
		if (err) {
			bpf_printk("vfs_read: error updating digit_state");
		}
	}

	bpf_printk("vfs_read: buf %x with size %d, total so far %d for pid %d", buf, count, bb.astate.total, pid);
	err = bpf_map_update_elem(&buffer, &pid, &bb, 0);
	if (err) {
		bpf_printk("vfs_read: error updating buffer");
	}

   return 0;
}

// For Day 1 Part 1
static long examine_char(u32 index, struct advent_state *astate) {
	
	if (index < ADVENT_BUFFER_LEN) {
		// bpf_printk("examine_char: [%d] %c (%d)", index, astate->buffer[index], astate->buffer[index]);
		char c = astate->buffer[index];
		if (c >= '0' && c <= '9') {
			if (astate->first_digit == -1) {
				astate->first_digit = c - '0';
			} 
			// Candidate for last digit
			astate->last_digit = c - '0';
		}

		// New line
		if (c == 10) {
			astate->total = astate->total + (astate->first_digit * 10) + astate->last_digit;
			astate->first_digit = -1;
			astate->last_digit = -1;
			astate->lines = astate->lines + 1;
			bpf_printk("examine_char: new line %d, total so far %d", astate->lines, astate->total);
		}
	}
	return 0;
}

// For Day 1 part 2, a straightforward solution
static long examine_char2(u32 index, struct advent_state *astate) {
	struct digit_state_t *ds = bpf_map_lookup_elem(&digit_state, &astate->pid);
	if (!ds) {
		bpf_printk("examine_char2: no digit state for pid %d", astate->pid);
		return 1;
	}

	s8 one = ds->text_digits[1];
	s8 two = ds->text_digits[2];
	s8 three = ds->text_digits[3];
	s8 four = ds->text_digits[4];
	s8 five = ds->text_digits[5];
	s8 six = ds->text_digits[6];
	s8 seven = ds->text_digits[7];
	s8 eight = ds->text_digits[8];
	s8 nine = ds->text_digits[9];

	if (index < ADVENT_BUFFER_LEN) {
		// bpf_printk("examine_char2: [%d] %c (%d)", index, astate->buffer[index], astate->buffer[index]);
		char c = astate->buffer[index];

		// one, two, three, four, five, six, seven, eight, nine
		switch (c){
			case 'e':  // one, three, five, seven, eight, nine
				if (one == 2) {c = '1';} one = 0;
				two = 0;
				if (three == 3) {three = 4;} 
					else {
						if (three == 4) {c = '3';} 
						three = 0;
					} 
				four = 0;
				if (five == 3) {c = '5';} five = 0;
				six = 0;
				if (seven == 1 || seven == 3) {seven++;} else {seven = 0;}
				eight = 1;
				if (nine == 3) {c = '9';} nine = 0;
				break;
			case 'f': // four, five
				one = 0; two = 0; three = 0; 
				four = 1;
				five = 1;
				six = 0; seven = 0; eight = 0; nine = 0;
				break;
			case 'g': // eight
				one = 0; two = 0; three = 0; four = 0; five = 0; 
				six = 0; seven = 0; nine = 0;
				eight = (eight == 2)? 3:0;
				break;
			case 'h': // three, eight
				one = 0; two = 0; 
				three = (three == 1)? 2:0;
				four = 0; five = 0; six = 0; seven = 0; 
				eight = (eight == 3)? 4:0;
				nine = 0;
				break;
			case 'i': //five, six, eight, nine 
				one = 0; two = 0; three = 0; four = 0; 
				five = (five == 1)? 2:0;
				six = (six == 1)? 2:0;
				seven = 0;
				eight = (eight == 1)? 2:0;
				nine = (nine == 1)? 2:0;
				break;
			case 'n': // one, seven, nine
				one = (one == 1)? 2:0;
				two = 0; three = 0; four = 0; five = 0; six = 0; 
				if (seven == 4) {c = '7';} seven = 0;
				eight = 0;
				if (nine == 0 || nine == 2) { nine++;} else {nine = 1;}
				break;
			case 'o': // one, two, four
				one = 1;
				if (two == 2) {c = '2';} two = 0;
				three = 0;
				four = (four == 1)? 2:0;
				five = 0; six = 0; seven = 0; eight = 0; nine = 0;
				break;
			case 'r': // three, four
				one = 0; two = 0; 
				three = (three == 2)? 3:0;
				if (four == 3) {c = '4';} four = 0;
				five = 0; six = 0; seven = 0; eight = 0; nine = 0;
				break;
			case 's': // six, seven
				one = 0; two = 0; three = 0; four = 0; five = 0; 
				six = 1;
				seven = 1;
				eight = 0; nine = 0;
				break;
			case 't': // two, three, eight
				one = 0; 
				two = 1;
				three = 1;
				four = 0; five = 0; six = 0; seven = 0; 
				if (eight == 4) {c = '8';} eight = 0;
				nine = 0;
				break;
			case 'u': // four
				one = 0; two = 0; three = 0; 
				four = (four == 2)? 3:0;
				five = 0; six = 0; seven = 0; eight = 0; nine = 0;
				break;
			case 'v': // five, seven
				one = 0; two = 0; three = 0; four = 0; six = 0; nine = 0;
				five = (five == 2)? 3:0;
				seven = (seven == 2)? 3:0;
				break;
			case 'w': // two
				one = 0;
				two = (two == 1)? 2:0;
				three = 0; four = 0; five = 0; six = 0; seven = 0; eight = 0; nine = 0;
				break;
			case 'x': // six
				one = 0; two = 0; three = 0; four = 0; five = 0;  
				if (six == 2) { c = '6';} six = 0;
				seven = 0; eight = 0; nine = 0;
				break;
			default:
				one = 0; two = 0; three = 0; four = 0; five = 0; six = 0; seven = 0; eight = 0; nine = 0;
				break;
		}

		if (c >= '0' && c <= '9') {
			if (astate->first_digit == -1) {
				// bpf_printk("examine_char2: first digit %c", c);
				astate->first_digit = c - '0';
			} 
			// bpf_printk("examine_char2: candidate last digit %c", c);
			astate->last_digit = c - '0';
		}

		if (c == 10) {
			if ((astate->first_digit < 0) || (astate->last_digit < 0)) {
				bpf_printk("No first or last digit to add");
			} else {
				astate->total = astate->total + (astate->first_digit * 10) + astate->last_digit;
				// bpf_printk("examine_char2: line %d first digit %d, last digit %d", astate->lines, astate->first_digit, astate->last_digit);
				bpf_printk("line %d, %d %d total: %d ", astate->lines + 1, astate->first_digit, astate->last_digit, astate->total);
			}

			astate->first_digit = -1;
			astate->last_digit = -1;
			astate->lines = astate->lines + 1;
			one = 0; two = 0; three = 0; four = 0; five = 0; six = 0; seven = 0; eight = 0; nine = 0;

			// bpf_printk("examine_char2: total so far %d", astate->total);
		}
	}

	ds->text_digits[1] = one;
	ds->text_digits[2] = two;
	ds->text_digits[3] = three;
	ds->text_digits[4] = four;
	ds->text_digits[5] = five;
	ds->text_digits[6] = six;
	ds->text_digits[7] = seven;
	ds->text_digits[8] = eight;
	ds->text_digits[9] = nine;
	bpf_map_update_elem(&digit_state, &astate->pid, ds, 0);

	return 0;
}

// For Day 1 Part 2, using a state machine (set up in day1.c)
static long examine_char3(u32 index, struct advent_state *astate) {
	struct state_input si;
	struct state_output *so;

	si.state = astate->table_state;;

	if (index < ADVENT_BUFFER_LEN) {
		// bpf_printk("examine_char3: [%d] %c (%d)", index, astate->buffer[index], astate->buffer[index]);
		char c = astate->buffer[index];
		si.input = c; 
		so = bpf_map_lookup_elem(&state_table, &si);
		if (so) {
			if (so->output > 0) {
				// bpf_printk("Found text for %d", so->output);
				c = so->output + '0';	
			}
			astate->table_state = so->new_state;
		} else {
			astate->table_state = 0;
			si.state = 0;
			// We might have the first char of a new word so run the input again
			so = bpf_map_lookup_elem(&state_table, &si);
			if (so) {
				astate->table_state = so->new_state;
			}
		}

		if (c >= '1' && c <= '9') {
			if (astate->first_digit == -1) {
				// bpf_printk("First digit %c", c);
				astate->first_digit = c - '0';
			} 
			// bpf_printk("Candidate last digit %c", c);
			astate->last_digit = c - '0';
		}
		if (c == 10) {
			astate->total = astate->total + (astate->first_digit * 10) + astate->last_digit;
			bpf_printk("line %d, %d %d total: %d ", astate->lines + 1, astate->first_digit, astate->last_digit, astate->total);
			astate->first_digit = -1;
			astate->last_digit = -1;
			astate->lines = astate->lines + 1;
			astate->table_state = 0;

		}
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
	astate.table_state = b->astate.table_state;
	astate.pid = pid;
	
	char *location;

	for (u8 j = 0; (j < LOOPS) && (b->offset < b->length); j++) {
		location = b->buf + b->offset;
		u32 read_length = b->length - b->offset; 
		if (read_length > ADVENT_BUFFER_LEN) {
			read_length = ADVENT_BUFFER_LEN;
		}
		bpf_printk("buffer_read: length %d, offset %d from %x, read %d chars", b->length, b->offset, b->buf, read_length);
		bpf_probe_read_user(astate.buffer, read_length, location);
		long ii = bpf_loop(read_length, EXAMINE_CHAR, &astate, 0);
		if (ii != read_length) {
			bpf_printk("buffer_read: surprise! %d loops != read_length %d");
		}
		b->offset += ADVENT_BUFFER_LEN;
	}

	b->astate.first_digit = astate.first_digit;
	b->astate.last_digit = astate.last_digit;
	b->astate.total = astate.total;
	b->astate.lines = astate.lines;
	b->astate.table_state = astate.table_state;
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
