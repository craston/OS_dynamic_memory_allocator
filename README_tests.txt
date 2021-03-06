The files provided for the tests are in the tests directory.

Files allocX.in files are examples of inputs for mem_shell. Don't
hesitate to write own scenarios. A short description of each of these
files is given below.

The syntax if ".in" files is simple. The only rule is to write 1
command per line. Three commands are available.
     - "aXX": asks for the allocation of a block of size XX.
     - "fY": asks to free the block allocated by the Y-th call to
     malloc
     - "q": tells the program to terminate

The mem_shell_sim program generates the expected output for a given
scenario. It allows you to check whether your allocator works as
expected. mem_shell_sim makes a few assumption about the way the
allocator works. You should follow these assumptions to be able to check
your allocator for correctness. Here are the rules to follow:
     - The list of free blocks is ordered according to increasing
     memory addresses 
     - The structures that define metadata for free and allocated
     blocks are called mem_free_block_t and mem_used_block_t
     respectively, and are both defined in file "mem_alloc_types.h"
     - The memory alignment is made based on the value MEM_ALIGNMENT
     defined in file "mem_alloc_types.h"
     - Calling memory_alloc() with a size 0 returns a valid pointer
     that can latter be freed.
     - Display functions are called appriopriatly.

If you followed all these rules, and mem_shell_sim generates a
different trace from the one generated by your allocator, but you are
sure your allocator is correct, please don't hesitate to send an email
to the teaching staff with information about your problematic
scenario. There can always be errors in the simulation.

alloc1.test: 

  This test is a simple sequence of memory allocation and should be
  the same whatever the allocation algorithm you use. It only aims at
  checking that the allocation mechanism works and does not need the free
  mechanism to be implemented.

alloc2.test:

  This test is the following of the previous one but frees the second
  and the fourth memory area. It aims at checking that your
  implementation of free is correct.

alloc3.test:

  This test is the following of the previous one and allocates two
  more chunks. The first fit strategy should get "fooled" by this
  allocation.

alloc4.test:

  This test is similar to the previous one except for the size of the
  last tow chunks that differs. The best fit strategy should get
  "fooled" by this allocation.

alloc5.test:

  This tests is meant to test that your free function merges
  contiguous free chunks of memory (no deferred coalescing!).

test_leak.test:

  This tests uses the LD_PRELOAD variable to replace the libc
  malloc,free, realloc by the one you defined in libmalloc.so. Then it
  runs the program leak_test.c which does recursive calls and
  leaks. You can easily check it using valgrind by hand (and without
  the LD_PRELOAD of course).

test_leak2.test:

  This tests keeps using the LD_PRELOAD variable to replace the libc
  malloc,free, realloc by the one you defined in libmalloc.so. Then it
  tests runs the program leak_test.c with a special argument which
  prevents it from leaking. Again, you can easily check this behavior
  using valgrind.
  

