// Dump the MAIN executable (MH_EXECUTE) of a running process from memory,
// after the protector has fixed up binding tables at runtime.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t*, mach_vm_size_t*, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t*, mach_port_t*);
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t*);
extern kern_return_t task_for_pid(mach_port_name_t, int, mach_port_name_t*);
static int find_pid(const char* name){
    int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_ALL,0}; size_t len=0;
    if(sysctl(mib,4,NULL,&len,NULL,0))return -1;
    struct kinfo_proc* p=malloc(len); if(!p)return -1;
    if(sysctl(mib,4,p,&len,NULL,0)){free(p);return -1;}
    int n=len/sizeof(struct kinfo_proc),pid=-1;
    for(int i=0;i<n;i++) if(!strncmp(p[i].kp_proc.p_comm,name,16)){pid=p[i].kp_proc.p_pid;break;}
    free(p); return pid;
}
static int rd(mach_port_name_t task,uint64_t a,void*b,uint64_t n){
    mach_vm_size_t got=0; return mach_vm_read_overwrite(task,a,n,(mach_vm_address_t)b,&got)==KERN_SUCCESS && got==n;
}
int main(int c,char**v){
    const char* t="Hay Day"; int pid=-1;
    if(c>=2){char*e;long x=strtol(v[1],&e,10); if(!*e)pid=(int)x; else t=v[1];}
    if(pid<=0)pid=find_pid(t);
    if(pid<=0){fprintf(stderr,"[!] %s not found\n",t);return 1;}
    mach_port_name_t task=0;
    if(task_for_pid(mach_task_self(),pid,&task)!=KERN_SUCCESS){fprintf(stderr,"[!] tfp fail\n");return 2;}
    fprintf(stderr,"[+] pid=%d task=%u\n",pid,task);
    // scan regions for MH_EXECUTE (magic feedfacf, filetype 2)
    mach_vm_address_t addr=1; mach_vm_size_t size=0;
    unsigned char hdr[4096];
    uint64_t mainbase=0;
    while(1){
        vm_region_basic_info_data_64_t info; mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64; mach_port_t on=0;
        if(mach_vm_region(task,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&on)!=KERN_SUCCESS)break;
        if((info.protection&VM_PROT_READ) && rd(task,addr,hdr,4096)){
            uint32_t magic=*(uint32_t*)hdr;
            if(magic==0xfeedfacf){
                uint32_t filetype=*(uint32_t*)(hdr+12);
                if(filetype==2){ mainbase=addr; fprintf(stderr,"[+] MH_EXECUTE @0x%llx\n",(unsigned long long)addr); break; }
            }
        }
        addr+=size; if(!addr)break;
    }
    if(!mainbase){fprintf(stderr,"[!] main exe not found\n");return 3;}
    // parse load commands to compute total vm span (max vmaddr+vmsize - base) and __LINKEDIT
    if(!rd(task,mainbase,hdr,4096)){fprintf(stderr,"[!] hdr read fail\n");return 4;}
    uint32_t ncmds=*(uint32_t*)(hdr+16);
    uint64_t off=32, maxend=0, linkedit_va=0, linkedit_sz=0, linkedit_foff=0;
    // may need more than 4096 for all load cmds; read 32KB
    unsigned char* lc=malloc(65536); rd(task,mainbase,lc,65536);
    off=32;
    for(uint32_t i=0;i<ncmds && off<65536;i++){
        uint32_t cmd=*(uint32_t*)(lc+off), cs=*(uint32_t*)(lc+off+4);
        if(cmd==0x19){ // LC_SEGMENT_64
            char* sn=(char*)(lc+off+8);
            uint64_t vmaddr=*(uint64_t*)(lc+off+24), vmsize=*(uint64_t*)(lc+off+32), foff=*(uint64_t*)(lc+off+40);
            uint64_t end=(vmaddr-*(uint64_t*)(lc+32+24)) ; // relative not reliable; use vmaddr
            if(vmaddr+vmsize > maxend) maxend=vmaddr+vmsize;
            if(!strcmp(sn,"__LINKEDIT")){ linkedit_va=vmaddr; linkedit_sz=vmsize; linkedit_foff=foff; }
        }
        off+=cs;
    }
    free(lc);
    uint64_t span = maxend - mainbase;
    if(span==0 || span>200u*1024*1024){ span=64u*1024*1024; }
    fprintf(stderr,"[*] span=0x%llx  linkedit va=0x%llx sz=0x%llx foff=0x%llx\n",
        (unsigned long long)span,(unsigned long long)linkedit_va,(unsigned long long)linkedit_sz,(unsigned long long)linkedit_foff);
    // dump full image in 8MB chunks
    FILE* f=fopen("mainmem.bin","wb"); if(!f){fprintf(stderr,"[!] open fail\n");return 5;}
    unsigned char* buf=malloc(8u*1024*1024); uint64_t done=0;
    while(done<span){
        uint64_t n=span-done; if(n>8u*1024*1024)n=8u*1024*1024;
        if(rd(task,mainbase+done,buf,n)) fwrite(buf,1,n,f);
        else { memset(buf,0,n); fwrite(buf,1,n,f); }
        done+=n;
    }
    fclose(f); free(buf);
    fprintf(stderr,"[+] dumped %llu bytes to mainmem.bin (base 0x%llx)\n",(unsigned long long)done,(unsigned long long)mainbase);
    printf("BASE=0x%llx SPAN=0x%llx LINKEDIT_VA=0x%llx LINKEDIT_SZ=0x%llx LINKEDIT_FOFF=0x%llx\n",
        (unsigned long long)mainbase,(unsigned long long)span,(unsigned long long)linkedit_va,(unsigned long long)linkedit_sz,(unsigned long long)linkedit_foff);
    return 0;
}
