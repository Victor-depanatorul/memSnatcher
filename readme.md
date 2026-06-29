# MemSnatcher - a cross-platform memory scanner

A **memory scanner** is a program that can read/write from a process, given it's pid.
Being cross-platform, it can do this on many operating systems.
For now, only the Windows version is integrated.  It will be integrated on Linux and macOS as well in the near future.

## How it works (for now):
You start by inputting the index of the type you want to search for. Then, all the processes opened are shown by pid : name. Enter the pid of the desired process. Then, you enter the index of the operation you want to use.