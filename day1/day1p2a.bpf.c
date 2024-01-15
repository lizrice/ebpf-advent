#include "day1p2.h"

// For Day 1 Part 2, using a state machine (set up in day1.c)
static long examine_char(u32 index, struct advent_state *astate) {
	struct state_input si;
	struct state_output *so;

	si.state = astate->table_state;;

	if (index < ADVENT_BUFFER_LEN) {
		// bpf_printk("examine_char p2a: [%d] %c (%d)", index, astate->buffer[index], astate->buffer[index]);
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
			bpf_printk("p2a: line %d, %d %d total: %d ", astate->lines + 1, astate->first_digit, astate->last_digit, astate->total);
			astate->first_digit = -1;
			astate->last_digit = -1;
			astate->lines = astate->lines + 1;
			astate->table_state = 0;
		}
	}
	return 0;
}
