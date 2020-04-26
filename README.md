# Memory Squander Snitch

_Expensive allocation snitch `LD_PRELOAD` module_

## The Problem

Detecting sources of expensive allocations in a program is not always trivial. By _expensive_, it can be either large amount of memory, but it can also be expensive CPU operations (releasing large memory blocks can also consumme a lot of precious cycles).

## The Solution

This `LD_PRELOAD` module allows to trace most glibc memory calls, plus some related ones (`memset` is typically something you want to monitor, especially in C++ code)

## What This Module Does

Trace every call to the following functions, and trigger backtraces when time and/or size threshold is reached:

* `aligned_alloc`
* `calloc`
* `free`
* `malloc`
* `memalign`
* `memset`
* `mmap`
* `mremap`
* `munmap`
* `posix_memalign`
* `pvalloc`
* `realloc`
* `reallocarray`
* `valloc`

### What About C++ `new` ?

As the C++ allocator calls lower-level C allocator, we obviously can trace them too.

## Building

```shell
cmake .
make
```

## Usage

```shell
LD_PRELOAD=libsquandersnitch.so your_program your_arguments ...
```

## Example

```shell
seq 1 1000000 | LD_PRELOAD=$PWD/libsquandersnitch.so sort >/dev/null
```

## Settings

The following environment variables can be defined to tune the thresholds:

* `SQUANDERSNITCH_TIME_US` : Elapsed time in microsecond the module start to snitch
* `SQUANDERSNITCH_SIZE` : Size in Bytes the module start to snitch

## How ?

This small library design is pretty straightforward:

* Define exported (strong) symbols that will override glibs weak symbols (`malloc`, `free`, e`memset`, etc.)
* Call original `glibc` symbols when possible not to mess with circular dependency hell (hint: `dlsym` is calling `malloc`)
* Call `RTLD_NEXT` symbol otherwise

A bit of fancy C++ syntaxic sugar has been used to ease helpers, but everything could probably be moved to plan C.

