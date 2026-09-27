// Entitled external memory reader for iOS (jailbroken / roothide)
// Reads a running process's memory via task_for_pid + mach_vm_read_overwrite
// (NO code injection, NO ptrace/debugger) -> stealthy vs Promon SHIELD.
// Hunts the decrypted Promon "bi.txt" (ASCII, ';'-separated records with '_' symbol names)
// and dumps candidate regions to files.
//
// Usage:  reader                 -> auto-find "Hay Day" pid
//         reader <pid>           -> use given pid
//         reader <pid> all       -> also dump EVERY readable region (big)
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

// mach_vm_* are not always in the public iOS SDK headers -> declare them.
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t*, mach_vm_size_t*,
                                    vm_region_flavor_t, vm_region_info_t,
                                    mach_msg_type_number_t*, mach_port_t*);
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                            mach_vm_address_t, mach_vm_size_t*);
extern kern_return_t task_for_pid(mach_port_name_t, int, mach_port_name_t*);

static int find_pid(const char* name){
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return -1;
    struct kinfo_proc* procs = (struct kinfo_proc*)malloc(len);
    if (!procs) return -1;
    if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) { free(procs); return -1; }
    int n = (int)(len / sizeof(struct kinfo_proc));
    int pid = -1;
    for (int i = 0; i < n; i++) {
        if (strncmp(procs[i].kp_proc.p_comm, name, 16) == 0) { pid = procs[i].kp_proc.p_pid; break; }
    }
    free(procs);
    return pid;
}

#define CAP (24u*1024u*1024u)   // max bytes read per region

int main(int argc, char** argv){
    const char* target = "Hay Day";
    int pid = -1;
    int dump_all = 0;
    if (argc >= 2) {
        // numeric pid or a name
        char* end; long v = strtol(argv[1], &end, 10);
        if (*end == '\0') pid = (int)v; else target = argv[1];
    }
    if (argc >= 3 && strcmp(argv[2], "all") == 0) dump_all = 1;
    if (pid <= 0) pid = find_pid(target);
    if (pid <= 0) { fprintf(stderr, "[!] process '%s' not found\n", target); return 1; }
    fprintf(stderr, "[*] target pid = %d\n", pid);

    mach_port_name_t task = 0;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[!] task_for_pid failed: kr=%d (%s)\n", kr, mach_error_string(kr));
        fprintf(stderr, "    (need task_for_pid-allow entitlement honored + run as root)\n");
        return 2;
    }
    fprintf(stderr, "[+] got task port %u\n", task);

    unsigned char* buf = (unsigned char*)malloc(CAP);
    if (!buf) { fprintf(stderr, "[!] oom\n"); return 3; }

    mach_vm_address_t addr = 1;
    mach_vm_size_t size = 0;
    int region_n = 0, dumped = 0;
    unsigned long long total_scanned = 0;

    while (1) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objName = 0;
        kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &infoCnt, &objName);
        if (kr != KERN_SUCCESS) break;   // no more regions
        region_n++;

        // only readable regions
        if (info.protection & VM_PROT_READ) {
            mach_vm_size_t want = size < CAP ? size : CAP;
            mach_vm_size_t got = 0;
            kr = mach_vm_read_overwrite(task, addr, want, (mach_vm_address_t)buf, &got);
            if (kr == KERN_SUCCESS && got > 0) {
                total_scanned += got;
                // score for bi.txt-like text
                unsigned long semi = 0, us = 0, printable = 0, dig = 0;
                unsigned long lim = (unsigned long)got;
                for (unsigned long j = 0; j < lim; j++) {
                    unsigned char c = buf[j];
                    if (c == ';') semi++;
                    else if (c == '_') us++;
                    else if (c >= '0' && c <= '9') dig++;
                    if ((c >= 32 && c < 127) || c == 9 || c == 10 || c == 13) printable++;
                }
                double pr = lim ? (double)printable / (double)lim : 0.0;
                int looks_bi = (semi > 200 && us > 50 && pr > 0.80);
                if (looks_bi || dump_all) {
                    char fn[128];
                    snprintf(fn, sizeof(fn), "dump_%llx_%s.bin",
                             (unsigned long long)addr, looks_bi ? "BI" : "raw");
                    FILE* f = fopen(fn, "wb");
                    if (f) { fwrite(buf, 1, (size_t)got, f); fclose(f); dumped++; }
                    fprintf(stderr,
                        "[%s] region @0x%llx size=0x%llx read=0x%llx  ; =%lu _=%lu dig=%lu pr=%.2f -> %s\n",
                        looks_bi ? "BI" : "  ", (unsigned long long)addr,
                        (unsigned long long)size, (unsigned long long)got, semi, us, dig, pr, fn);
                }
            }
        }
        addr += size;
        if (addr == 0) break;
    }
    free(buf);
    fprintf(stderr, "[*] done. regions=%d scanned=%lluMB dumped=%d\n",
            region_n, total_scanned/(1024*1024), dumped);
    if (dumped == 0)
        fprintf(stderr, "[*] no bi.txt-like region found (maybe not decrypted yet / already freed). "
                        "Run right after launch, or retry a few times.\n");
    return 0;
}
