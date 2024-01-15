#define ADVENT_BUFFER_LEN 300

struct advent_state {
   // Running total 
   u16 total;   
   // Number of lines dealt with so far - only used for debugging
   u16 lines;

   // First & last digit in the line we're currently processing 
   s8 first_digit;
   s8 last_digit;

   // current state in the number-parsing FSM
   // Only used in p2A
   char table_state;

   // Copy of a section of the file being ready
   char buffer[ADVENT_BUFFER_LEN];

   // PID for this task. Only used in p2 to look up the digit state
   u32 pid;
};

// Used by examine_char2
// text_digits[1] = 0 if no characters from 'one'
//            [1] = 1 if we found 'o'
//            [1] = 2 if we found 'o' followed by 'n'
struct digit_state_t {
	s8 text_digits[10]; 
};

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

