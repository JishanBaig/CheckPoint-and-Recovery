## What is checkpointing and why is it necessary?

## What happens after process failure?

## How to recover a process state?

## Checkpointing
The software uses ptrace() system call and /proc directory entries to get context of the process. 
To start tracing a process following command is used:
ptrace(PTRACE_ATTACH, traced_proc, NULL, NULL);
Registers are read  with following system call.
ptrace(PTRACE_GETREGS,traced_proc,NULL, &regs);
Signal mask is stored with following system call.
ptrace(PTRACE_GETSIGMASK,traced_proc,NULL,&mask);

To dump to pages from the memory of the process, first we read /proc/[pid]/maps files and fetch virtual start address and permission information. Then we read actual content of the memory from /proc/[pid]/mem directory with the address read from maps files. We store binary data into code file. This data read size is in multiple of page size. We store starting address, number of pages mapped from that starting address, and permission bits to pagesmap file.

## Recovery
To recover a process from its checkpoint data first we create a child process and trace it with 
ptrace(PTRACE_ATTACH, traced_proc, NULL, NULL);
Then from parent process we restore child’s registers  with following system call.
ptrace(PTRACE_SETREGS,traced_proc,NULL, &regs);
Signal mask is restored with following system call.
ptrace(PTRACE_SETSIGMASK,traced_proc,NULL,&mask);

Next to restore  memory of the process we first read pagesmap file to get start address, protection info bits and number of pages mapped to given starting address. Then we read code file in multiple of page size and use mmap() system call. After this step child will continue its execution.
