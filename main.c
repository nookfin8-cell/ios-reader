// Entitled external memory reader for iOS (jailbroken / roothide)
// Reads a running process's memory via task_for_pid + mach_vm_read_overwrite
// (NO injection, NO ptrace) -> stealthy vs Promon SHIELD.
// Hunts the decrypted Promon "bi.txt" binding-info (records with ";0;"/";5;"/";10;"
// indicators and C/C++/ObjC symbol names) and dumps matching regions.
//
// Usage:
//   reader                 -> one scan of "Hay Day"
//   reader <pid|name>      -> one scan of given target
//   reader <pid|name> loop <seconds>  -> scan repeatedly (catch bi.txt during startup)
//   reader <pid|name> all  -> dump EVERY readable region (big!)
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

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
    for (int i = 0; i < n; i++)
        if (strncmp(procs[i].kp_proc.p_comm, name, 16) == 0) { pid = procs[i].kp_proc.p_pid; break; }
    free(procs);
    return pid;
}

#define CAP (32u*1024u*1024u)

// count non-overlapping occurrences of needle in [buf,buf+len)
static unsigned long countsub(const unsigned char* buf, unsigned long len, const char* ndl){
    unsigned long nl = strlen(ndl), c = 0;
    if (nl == 0 || len < nl) return 0;
    for (unsigned long i = 0; i + nl <= len; i++) {
        unsigned long j = 0;
        while (j < nl && buf[i+j] == (unsigned char)ndl[j]) j++;
        if (j == nl) { c++; i += nl - 1; }
    }
    return c;
}

static int scan_once(mach_port_name_t task, int dump_all, int pass){
    unsigned char* buf = (unsigned char*)malloc(CAP);
    if (!buf) return -1;
    mach_vm_address_t addr = 1; mach_vm_size_t size = 0;
    int dumped = 0;
    while (1) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objName = 0;
        if (mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &infoCnt, &objName) != KERN_SUCCESS) break;
        if (info.protection & VM_PROT_READ) {
            mach_vm_size_t want = size < CAP ? size : CAP, got = 0;
            if (mach_vm_read_overwrite(task, addr, want, (mach_vm_address_t)buf, &got) == KERN_SUCCESS && got > 64) {
                unsigned long lim = (unsigned long)got, semi=0, us=0, dig=0, pr=0;
                for (unsigned long j=0;j<lim;j++){ unsigned char c=buf[j];
                    if(c==';')semi++; else if(c=='_')us++; else if(c>='0'&&c<='9')dig++;
                    if((c>=32&&c<127)||c==9||c==10||c==13)pr++; }
                double prr = (double)pr/(double)lim;
                unsigned long ind = countsub(buf,lim,";0;")+countsub(buf,lim,";5;")+countsub(buf,lim,";10;");
                unsigned long mangled = countsub(buf,lim,"_Z")+countsub(buf,lim,"__Z");
                // WINDOWED: scan this region in 128KB windows to isolate the small bi.txt
                // TEXT block embedded inside big binary heap regions.
                unsigned long WIN=128*1024;
                for (unsigned long w=0; w+4096<=lim; w+=WIN) {
                    unsigned long wl = (w+WIN<=lim)? WIN : (lim-w);
                    const unsigned char* wb = buf+w;
                    unsigned long wsemi=0,wpr=0,wus=0;
                    for (unsigned long j=0;j<wl;j++){unsigned char c=wb[j]; if(c==';')wsemi++; if(c=='_')wus++; if((c>=32&&c<127)||c==9||c==10||c==13)wpr++;}
                    double wprr=(double)wpr/(double)wl;
                    // catch ANY decrypted TEXT file window (bi/ii/config): high printable + identifier/symbol heavy
                    if (wprr>0.90 && (wus>80 || wsemi>40)) {
                        char fn[160];
                        snprintf(fn,sizeof(fn),"txt_%llx.bin",(unsigned long long)(addr+w));
                        FILE* f=fopen(fn,"wb"); if(f){fwrite(wb,1,(size_t)wl,f);fclose(f);dumped++;}
                        fprintf(stderr,"[TXT] @0x%llx win+0x%lx  ;=%lu _=%lu pr=%.2f -> %s\n",
                            (unsigned long long)addr,w,wsemi,wus,wprr,fn);
                    }
                }
                if (dump_all) {
                    char fn[160]; snprintf(fn,sizeof(fn),"raw_%llx.bin",(unsigned long long)addr);
                    FILE* f=fopen(fn,"wb"); if(f){fwrite(buf,1,(size_t)got,f);fclose(f);}
                }
                if (ind>50)
                    fprintf(stderr,"[? ] @0x%llx sz=0x%llx ;=%lu ind=%lu mZ=%lu pr=%.2f\n",
                        (unsigned long long)addr,(unsigned long long)size,semi,ind,mangled,prr);
            }
        }
        addr += size; if (addr==0) break;
    }
    free(buf);
    return dumped;
}

int main(int argc, char** argv){
    const char* target = "Hay Day"; int pid=-1, dump_all=0, loop_s=0;
    if (argc>=2){ char* e; long v=strtol(argv[1],&e,10); if(*e=='\0') pid=(int)v; else target=argv[1]; }
    if (argc>=3 && strcmp(argv[2],"all")==0) dump_all=1;
    if (argc>=4 && strcmp(argv[2],"loop")==0) loop_s=atoi(argv[3]);
    if (pid<=0) pid=find_pid(target);
    if (pid<=0){ fprintf(stderr,"[!] '%s' not found\n",target); return 1; }
    fprintf(stderr,"[*] target pid=%d\n",pid);
    mach_port_name_t task=0;
    kern_return_t kr=task_for_pid(mach_task_self(),pid,&task);
    if(kr!=KERN_SUCCESS){ fprintf(stderr,"[!] task_for_pid kr=%d (%s)\n",kr,mach_error_string(kr)); return 2; }
    fprintf(stderr,"[+] task port %u\n",task);
    if (loop_s>0){
        int total=0;
        for(int p=0; p<loop_s*4; p++){   // ~4 scans/sec-ish
            int d=scan_once(task,dump_all,p);
            if(d>0){ total+=d; fprintf(stderr,"[*] pass %d dumped %d\n",p,d); }
            // re-resolve pid could have changed on relaunch; keep same task
            usleep(250000);
        }
        fprintf(stderr,"[*] loop done, total BI dumps=%d\n",total);
    } else {
        int d=scan_once(task,dump_all,0);
        fprintf(stderr,"[*] done. BI dumps=%d\n",d);
    }
    return 0;
}
