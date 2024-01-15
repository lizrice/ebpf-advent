#define ADVENT_BUFFER_LEN 400

struct advent_state {
   // Running total 
   u16 total;   
   // Number of lines dealt with so far - only used for debugging
   u16 lines;

   // First & last digit in the line we're currently processing 
   s8 first_digit;
   s8 last_digit;

   // Copy of a section of the file being ready
   char buffer[ADVENT_BUFFER_LEN];
};