/**
 * Squander Snitch, allocation hot spot tracer. Allows to print stack traces and statistics on "hot" allocation
 * related events (malloc, free, memset..) when certain threshold (size involved and/or time spent in the function)
 * is reached.
 * Thanks to Algolia for giving me the opportunity to develop this tools!
 * @maintainer Xavier Roche (xavier dot roche at algolia.com)
 */

#include <cstdio>
#include <cstddef>
#include <cstdarg>
#include <dlfcn.h>
#include <array>

#include <cstdlib>
#include <sys/types.h>
#include <sys/mman.h>
#include <cassert>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <chrono>
#include <type_traits>
#include <unistd.h>
#include <execinfo.h>

// Trace glibc allocations ?
#define TRACE_GLIBC_ALLOCS

using namespace std::chrono_literals;

#define assertm(exp, msg) assert(((void)msg, exp))

// Default threshold
namespace default_threshold {
const signed long slowTimeUsThreshold = 1000;
const std::size_t sizeThreshold = 10000000;
};

static unsigned long toLong(const char* const s, unsigned long defaultValue)
{
    if (s != nullptr && *s != '\0') {
        unsigned long l = 0;
        for (std::size_t i = 0; s[i]; i++) {
            const unsigned char c = s[i];
            if (c >= '0' && c <= '9') {
                l *= 10;
                l += c - '0';
            } else {
                abort();
            }
        }
        if (l != 0) {
            return l;
        }
    }
    return defaultValue;
}

/** Ignored return value **/
template<typename T>
void ignored_result(T) {
}

/** Class aimed to spot slow functions or big allocation spots. **/
class WarnSlow
{
public:
    WarnSlow(const char* const name)
      : _name(name)
    {}

    ~WarnSlow()
    {
        const std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        const auto elapsed = end - _start;
        const auto elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
        if (_size >= sizeThreshold || elapsedUs >= slowTimeUsThreshold) {
            char buffer[256];
            if (_size != 0) {
                snprintf(buffer,
                         sizeof(buffer),
                         "%s <%zuB> <%zu.%03zums>\n",
                         _name,
                         _size,
                         (std::size_t)(elapsedUs / 1000),
                         (std::size_t)(elapsedUs % 1000));
            } else {
                snprintf(buffer,
                         sizeof(buffer),
                         "%s <%zd.%03zums>\n",
                         _name,
                         (std::size_t)(elapsedUs / 1000),
                         (std::size_t)(elapsedUs % 1000));
            }
            ignored_result(write(STDERR_FILENO, buffer, std::strlen(buffer)));
            _backtrace();
        }
    }

    inline void setSize(std::size_t size) { _size = size; }

private:
    void _backtrace()
    {
        constexpr const std::size_t bufferSize = 64;
        void* buffer[bufferSize];
        const auto nbTraces = backtrace(buffer, bufferSize);
        backtrace_symbols_fd(buffer, nbTraces, STDERR_FILENO);
    }

private:
    const signed long slowTimeUsThreshold =
        toLong(getenv("SQUANDERSNITCH_TIME_US"), default_threshold::slowTimeUsThreshold);
    const std::size_t sizeThreshold = toLong(getenv("SQUANDERSNITCH_SIZE"), default_threshold::sizeThreshold);

private:
    std::size_t _size = 0;

private:
    const std::chrono::steady_clock::time_point _start = std::chrono::steady_clock::now();
    const char* const _name;
};

/* Helper: get a glibc symbol */
template<typename F>
auto get_libc(const char* const name)
{
    const auto ptr = dlsym(RTLD_NEXT, name);
    assertm(ptr != nullptr, "Unable to find libc symbol");
    return reinterpret_cast<F>(ptr);
}

/* Helper: get a glibc symbol once */
template<typename F>
auto get_libc_static(const char* const name)
{
    static const auto fun = get_libc<F>(name);
    return fun;
}

/* Helper: forward a function call with slow/big threshold checks */
template<typename F, typename... Ts>
auto forward_libc_function(F function, const char* const name, std::size_t size, Ts... args)
{
    WarnSlow check(name);
    if (size != 0) {
        check.setSize(size);
    }
    return function(args...);
}

/* Helper: take an original function from glibc, and forward it with slow/big threshold checks */
template<typename F, typename... Ts>
auto forward_libc_size(const char* const name, std::size_t size, Ts... args)
{
    const auto fun = get_libc_static<F>(name);
    return forward_libc_function(fun, name, size, args...);
}

/* Helper: take an original function from glibc, and forward it with slow threshold checks */
template<typename F, typename... Ts>
auto forward_libc(const char* const name, Ts... args)
{
    return forward_libc_size<F, Ts...>(name, 0, args...);
}

// Exported strong symbols.
extern "C"
{
    // Forward glibc declarations to be able to call them. We don't want to mess with dlsym() for those low-level
    // functions, as dlsym() itself calls allocators. Fortunately glibc folks were smart enough to provide us
    // original symbols.

#ifdef TRACE_GLIBC_ALLOCS
    extern void* __libc_malloc(size_t size);
    extern void* __libc_memalign(size_t alignment, size_t size);
    extern int __libc_posix_memalign(void** memptr, size_t alignment, size_t size);
    extern void* __libc_aligned_alloc(size_t alignment, size_t size);
    extern void* __libc_valloc(size_t size);
    extern void* __libc_pvalloc(size_t size);
    extern void __libc_free(void* ptr);
    extern void* __libc_calloc(size_t nmemb, size_t size);
    extern void* __libc_realloc(void* ptr, size_t size);
    extern void* __libc_reallocarray(void* ptr, size_t nmemb, size_t size);

    void* malloc(size_t size) { return forward_libc_function(__libc_malloc, "malloc", std::size_t(size), size); }

    void* memalign(size_t alignment, size_t size)
    {
        return forward_libc_function(__libc_memalign, "memalign", std::size_t(size), alignment, size);
    }

    int posix_memalign(void** memptr, size_t alignment, size_t size)
    {
        *memptr = forward_libc_function(__libc_memalign, "posix_memalign", std::size_t(size), alignment, size);
        if (*memptr != nullptr || size == 0) {
            return 0;
        } else {
            return 1;
        }
    }

    void* aligned_alloc(size_t alignment, size_t size)
    {
        return forward_libc_function(__libc_memalign, "aligned_alloc", std::size_t(size), alignment, size);
    }

    void* valloc(size_t size) { return forward_libc_function(__libc_valloc, "valloc", std::size_t(size), size); }

    void* pvalloc(size_t size)
    {
        return forward_libc_function(__libc_pvalloc, "pvalloc", std::size_t(size), size);
    }

    void* calloc(size_t nmemb, size_t size)
    {
        return forward_libc_function(__libc_calloc, "calloc", std::size_t(nmemb * size), nmemb, size);
    }

    void* realloc(void* ptr, size_t size)
    {
        return forward_libc_function(__libc_realloc, "realloc", std::size_t(size), ptr, size);
    }

    void* reallocarray(void* ptr, size_t nmemb, size_t size)
    {
        return forward_libc_function(
            __libc_reallocarray, "reallocarray", std::size_t(nmemb * size), ptr, nmemb, size);
    }

    void free(void* ptr) { return forward_libc_function(__libc_free, "free", 0, ptr); }
#endif

    // Regular forwards, using RTLD_NEXT

    void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
    {
        const bool anonymous = (flags & MAP_ANONYMOUS) != 0;
        if (anonymous) {
            return forward_libc_size<decltype(mmap)*>(
                "mmap", std::size_t(length), addr, length, prot, flags, fd, offset);
        } else {
            return forward_libc<decltype(mmap)*>("mmap", addr, length, prot, flags, fd, offset);
        }
    }

    int munmap(void* addr, size_t length) { return forward_libc<decltype(munmap)*>("munmap", addr, length); }

    void* mremap(void* old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */)
    {
        // Extract fifth argument with MREMAP_FIXED
        void* new_addr = nullptr;
        if ((flags & MREMAP_FIXED)) {
            va_list ap;
            va_start(ap, flags);
            new_addr = va_arg(ap, void*);
            va_end(ap);
        }

        const bool anonymous = (flags & MAP_ANONYMOUS) != 0;
        if (anonymous) {
            return forward_libc_size<decltype(mremap)*>(
                "mremap", std::size_t(new_size), old_address, old_size, new_size, flags, new_addr);
        } else {
            return forward_libc<decltype(mremap)*>("mremap", old_address, old_size, new_size, flags, new_addr);
        }
    }

    void* memset(void* s, int c, size_t n)
    {
        return forward_libc_size<decltype(memset)*>("memset", std::size_t(n), s, c, n);
    }
};
