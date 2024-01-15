#include "day1p2.h"

// For Day 1 part 2, a straightforward solution
static long examine_char(u32 index, struct advent_state *astate) {
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
		// bpf_printk("examine_char p2: [%d] %c (%d)", index, astate->buffer[index], astate->buffer[index]);
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
				bpf_printk("examine_char p2: line %d, %d %d total: %d ", astate->lines + 1, astate->first_digit, astate->last_digit, astate->total);
			}

			astate->first_digit = -1;
			astate->last_digit = -1;
			astate->lines = astate->lines + 1;
			one = 0; two = 0; three = 0; four = 0; five = 0; six = 0; seven = 0; eight = 0; nine = 0;

			bpf_printk("examine_char p2: total so far %d", astate->total);
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



