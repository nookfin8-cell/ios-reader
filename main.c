// Fast external memory reader for iOS (jailbroken/roothide).
// task_for_pid + mach_vm_read_overwrite, NO injection.
// FAST: single-pass printable scan in 128KB windows, dumps decrypted TEXT files.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
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
#define CAP (24u*1024u*1024u)
static int scan_once(mach_port_name_t task,int pass){
    unsigned char* buf=malloc(CAP); if(!buf)return -1;
    mach_vm_address_t addr=1; mach_vm_size_t size=0; int dumped=0;
    while(1){
        vm_region_basic_info_data_64_t info; mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64; mach_port_t on=0;
        if(mach_vm_region(task,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&on)!=KERN_SUCCESS)break;
        // skip non-readable and HUGE regions (>96MB) for speed
        if((info.protection&VM_PROT_READ) && size <= 96u*1024u*1024u){
            mach_vm_size_t want=size<CAP?size:CAP, got=0;
            if(mach_vm_read_overwrite(task,addr,want,(mach_vm_address_t)buf,&got)==KERN_SUCCESS && got>4096){
                unsigned long lim=got, WIN=128*1024;
                for(unsigned long w=0; w+8192<=lim; w+=WIN){
                    unsigned long wl=(w+WIN<=lim)?WIN:(lim-w); const unsigned char* b=buf+w;
                    unsigned long pr=0,us=0,se=0;
                    for(unsigned long j=0;j<wl;j++){unsigned char c=b[j]; if(c=='_')us++; else if(c==';')se++; if((c>=32&&c<127)||c==9||c==10||c==13)pr++;}
                    if((double)pr/wl>0.90 && (us>80||se>40)){
                        char fn[128]; snprintf(fn,sizeof(fn),"txt_%llx.bin",(unsigned long long)(addr+w));
                        FILE* f=fopen(fn,"wb"); if(f){fwrite(b,1,wl,f);fclose(f);dumped++;}
                    }
                }
            }
        }
        addr+=size; if(!addr)break;
    }
    free(buf); return dumped;
}
int main(int c,char**v){
    const char* t="Hay Day"; int pid=-1,loop=0;
    if(c>=2){char*e; long x=strtol(v[1],&e,10); if(!*e)pid=(int)x; else t=v[1];}
    if(c>=4 && !strcmp(v[2],"loop")) loop=atoi(v[3]);
    if(pid<=0)pid=find_pid(t);
    if(pid<=0){fprintf(stderr,"[!] %s not found\n",t);return 1;}
    mach_port_name_t task=0;
    if(task_for_pid(mach_task_self(),pid,&task)!=KERN_SUCCESS){fprintf(stderr,"[!] tfp fail\n");return 2;}
    fprintf(stderr,"[+] pid=%d task=%u\n",pid,task);
    if(loop>0){ int tot=0; time_t end=time(0)+loop; int p=0;
        while(time(0)<end){ int d=scan_once(task,p++); tot+=d; fprintf(stderr,"[pass %d] dumped=%d\n",p,d);} 
        fprintf(stderr,"[*] loop done total=%d\n",tot);
    } else { fprintf(stderr,"[*] dumped=%d\n",scan_once(task,0)); }
    return 0;
}
