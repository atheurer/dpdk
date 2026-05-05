#!/bin/bash
# Check prerequisites for testpmd jitter eBPF instrumentation.
# Exit 0 if all required checks pass, non-zero otherwise.

pass=0
fail=0
warn=0

check_pass() {
    echo "  PASS: $1"
    ((pass++))
}

check_fail() {
    echo "  FAIL: $1"
    ((fail++))
}

check_warn() {
    echo "  WARN: $1"
    ((warn++))
}

echo "=== testpmd jitter eBPF prerequisites ==="
echo

# 1. Kernel version >= 5.5 (BPF_F_MMAPABLE support)
echo "[Kernel version]"
kver=$(uname -r)
kmajor=$(echo "$kver" | cut -d. -f1)
kminor=$(echo "$kver" | cut -d. -f2)
if [ "$kmajor" -gt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -ge 5 ]; }; then
    check_pass "Linux $kver (>= 5.5 required for BPF_F_MMAPABLE)"
else
    check_fail "Linux $kver — need >= 5.5 for BPF_F_MMAPABLE array maps"
fi
echo

# 2. BTF support (CONFIG_DEBUG_INFO_BTF=y)
echo "[BTF support]"
if [ -f /sys/kernel/btf/vmlinux ]; then
    check_pass "/sys/kernel/btf/vmlinux exists (CONFIG_DEBUG_INFO_BTF=y)"
else
    check_fail "/sys/kernel/btf/vmlinux not found — kernel needs CONFIG_DEBUG_INFO_BTF=y"
    echo "         Most distro kernels (Fedora, RHEL 8+, Ubuntu 20.10+) have this enabled."
fi
echo

# 3. clang (BPF program compiler)
echo "[clang]"
if command -v clang &>/dev/null; then
    clang_ver=$(clang --version 2>/dev/null | head -1)
    check_pass "$clang_ver"
else
    check_fail "clang not found"
    echo "         Install: dnf install clang  (Fedora/RHEL)"
    echo "                  apt install clang  (Debian/Ubuntu)"
fi
echo

# 4. bpftool (skeleton generation)
echo "[bpftool]"
if command -v bpftool &>/dev/null; then
    bpftool_ver=$(bpftool version 2>/dev/null | head -1)
    check_pass "$bpftool_ver"
else
    check_fail "bpftool not found"
    echo "         Install: dnf install bpftool  (Fedora/RHEL)"
    echo "                  apt install linux-tools-common linux-tools-$(uname -r)  (Debian/Ubuntu)"
fi
echo

# 5. libbpf development headers
echo "[libbpf-devel]"
libbpf_found=0
if pkg-config --exists libbpf 2>/dev/null; then
    libbpf_ver=$(pkg-config --modversion libbpf 2>/dev/null)
    check_pass "libbpf $libbpf_ver (via pkg-config)"
    libbpf_found=1
elif [ -f /usr/include/bpf/libbpf.h ]; then
    check_pass "/usr/include/bpf/libbpf.h found"
    libbpf_found=1
else
    check_fail "libbpf development headers not found"
    echo "         Install: dnf install libbpf-devel  (Fedora/RHEL)"
    echo "                  apt install libbpf-dev  (Debian/Ubuntu)"
fi

if [ "$libbpf_found" -eq 1 ]; then
    # Check minimum version (need >= 0.5 for skeleton + mmapable)
    if pkg-config --exists libbpf 2>/dev/null; then
        libbpf_ver=$(pkg-config --modversion libbpf 2>/dev/null)
        libbpf_major=$(echo "$libbpf_ver" | cut -d. -f1)
        libbpf_minor=$(echo "$libbpf_ver" | cut -d. -f2)
        if [ "$libbpf_major" -gt 0 ] || { [ "$libbpf_major" -eq 0 ] && [ "$libbpf_minor" -ge 5 ]; }; then
            check_pass "libbpf version $libbpf_ver >= 0.5"
        else
            check_fail "libbpf version $libbpf_ver — need >= 0.5 for skeleton and BPF_F_MMAPABLE"
        fi
    fi
fi
echo

# 6. Required tracepoints
echo "[Tracepoints]"
tracefs=""
if [ -d /sys/kernel/debug/tracing/events ]; then
    tracefs=/sys/kernel/debug/tracing/events
elif [ -d /sys/kernel/tracing/events ]; then
    tracefs=/sys/kernel/tracing/events
fi

if [ -z "$tracefs" ]; then
    check_warn "tracefs not accessible (try running as root or: mount -t tracefs tracefs /sys/kernel/tracing)"
else
    if [ -d "$tracefs/sched/sched_switch" ]; then
        check_pass "sched:sched_switch tracepoint available"
    else
        check_fail "sched:sched_switch tracepoint not found at $tracefs/sched/sched_switch"
    fi

    if [ -d "$tracefs/irq/irq_handler_entry" ]; then
        check_pass "irq:irq_handler_entry tracepoint available"
    else
        check_fail "irq:irq_handler_entry tracepoint not found at $tracefs/irq/irq_handler_entry"
    fi

    if [ -d "$tracefs/irq/softirq_entry" ]; then
        check_pass "irq:softirq_entry tracepoint available (optional)"
    else
        check_warn "irq:softirq_entry tracepoint not found (optional, softirq tracking will be unavailable)"
    fi
fi
echo

# 7. BPF capability
echo "[BPF capability]"
if [ "$(id -u)" -eq 0 ]; then
    check_pass "Running as root (CAP_BPF implied)"
else
    # Check for CAP_BPF or CAP_SYS_ADMIN on the current process
    if command -v capsh &>/dev/null; then
        caps=$(capsh --print 2>/dev/null)
        if echo "$caps" | grep -qE 'cap_bpf|cap_sys_admin'; then
            check_pass "CAP_BPF or CAP_SYS_ADMIN capability detected"
        else
            check_warn "Not root and no CAP_BPF/CAP_SYS_ADMIN detected"
            echo "         testpmd typically runs as root for hugepage/DPDK access, so this is usually fine."
            echo "         At runtime, CAP_BPF (or CAP_SYS_ADMIN) is needed to load BPF programs."
        fi
    else
        check_warn "Not root — cannot verify capabilities (capsh not found)"
        echo "         testpmd typically runs as root. CAP_BPF is needed to load BPF programs."
    fi
fi
echo

# 8. Verify clang can compile BPF targets
echo "[clang BPF target]"
if command -v clang &>/dev/null; then
    bpf_test=$(mktemp /tmp/bpf_test_XXXXXX.c)
    cat > "$bpf_test" <<'BPF_EOF'
typedef unsigned long long u64;
typedef unsigned int u32;
void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
int probe(void *ctx) { return 0; }
BPF_EOF
    bpf_out="${bpf_test%.c}.o"
    if clang -target bpf -O2 -c "$bpf_test" -o "$bpf_out" 2>/dev/null; then
        check_pass "clang can compile BPF target"
        rm -f "$bpf_out"
    else
        check_fail "clang cannot compile with -target bpf"
        echo "         Try: clang -target bpf -O2 -c test.c -o test.o"
    fi
    rm -f "$bpf_test"
else
    check_fail "clang not installed (skipping BPF target test)"
fi
echo

# Summary
echo "=== Summary ==="
echo "  $pass passed, $fail failed, $warn warnings"
echo

if [ "$fail" -gt 0 ]; then
    echo "Some required checks failed. Install missing dependencies before proceeding."
    echo
    echo "Quick install (Fedora/RHEL):"
    echo "  sudo dnf install libbpf-devel clang bpftool"
    echo
    echo "Quick install (Debian/Ubuntu):"
    echo "  sudo apt install libbpf-dev clang linux-tools-common"
    exit 1
else
    echo "All required checks passed. Ready to build eBPF jitter instrumentation."
    exit 0
fi
