# Advent of Code 2023 Day1

My challenge to myself: implement the Advent of Code challenges entirely in
eBPF. Having done these challenges before I know the input is essentially a
file. I want to simply be able to `cat` the input file, and have eBPF tell me
the answer. None of the problem-solving logic is to be in user space - all I'm
allowing myself to do in user space is load the BPF programs, initialize and 
load maps, and output the results. 

I've used a kernel v6.5.0 as supplied in Ubuntu 23.10

https://github.com/lizrice/ebpf-advent/assets/458616/d5c7d3ca-0510-485b-b5d5-7f40a531046e

## Day 1 Part 1

In line 16 define `EXAMINE_CHAR` to `examine_char`.

The kprobe attached to vfs_open() lets us ignore files that we're not interested
in, being read by any other executables. 

In the kprobe attached to vfs_read() we can get the address of the buffer that
data will be read into, but it won't be populated at that point. Parsing the
contents of the buffer is triggered by the kretprobe for vfs_read(). 

### File parsing

`cat` reads into a 128k buffer. In this challenge (at least for the puzzle input 
I was given) the input file is 21760 bytes long. I copied the buffer memory section by section 
into a local buffer size ADVENT_BUFFER_LEN. Since this buffer lives on the stack it
can't be arbitrarily large (in fact I had to adjust the size for the different
`examine_char*` implementations.) By using a combination of loops and recursively calling 
the tail call `buffer_read` I've been able to parse enough characters to solve this challenge. 

## Day 1 Part 2

There are two solutions here. Define `EXAMINE_CHAR` to either `examine_char2` or `examine_char3`. 

The version implemented in `examine_char3` uses an FSM to parse the digits. This uses less stack 
space, so I can use a larger size for ADVENT_BUFFER_LEN (which would allow for parsing a bigger 
file if necessary).

---
If you want to learn more about eBPF, you might want to check out my repo and book [Learning eBPF](https://github.com/lizrice/learning-ebpf)
