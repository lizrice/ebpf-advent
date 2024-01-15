#include "day1p1.h"

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
