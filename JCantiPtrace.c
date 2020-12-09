#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/ptrace.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>

#if defined(__aarch64__)
	#define pt_regs user_pt_regs
	#define uregs regs
	#define ARM_r0 regs[0]
	#define ARM_r7 regs[7]
	#define ARM_1r regs[30]
	#define ARM_sp sp
	#define ARM_pc pc
	#define ARM_cpsr pstate
	#define NT_PRSTATUS 1
	#define NT_foo 1
#endif

void hookSysCallBefore(pid_t pid,pid_t pid2);
void hookSysCallAfter(pid_t pid);
long getSysCallNo(int pid,struct pt_regs* regs);
extern int errno;

int main(int argc,char* argv[]){
    // -d -p <pid> -z <100> -s <appname>
    int debug = atoi(argv[1]);
    int pid = atoi(argv[2]);
    char* appname = argv[3];
	int pid2 = atoi(argv[4]);
	printf("pid: %d\n",pid);
	printf("appname: %s\n",appname);
	// 附加到zygote进程
	int res = ptrace(PTRACE_ATTACH,pid,0,0);
	printf("res: %d\n",res);
	// 等待附加完成
    waitpid(pid, NULL, 0);


    // 拦截 zygote 进程的 fork
    //if (ptrace(PTRACE_SETOPTIONS, pid, (void *)1, (void *)(PTRACE_O_TRACEFORK))) {
	res = ptrace(PTRACE_SETOPTIONS, pid, (void *)0, (void *)(PTRACE_O_TRACEFORK));
	printf("res: %d\n",res);
	printf("errno: %d\n",errno);
    if (res == -1) {
        printf("FATAL ERROR: ptrace(PTRACE_SETOPTIONS, ...)\n");
        return -1;
    }
    ptrace(PTRACE_CONT, pid, (void *)1, 0);
    int t;
    int stat;
    int child_pid = 0;
    int zygote = 0;

    for (;;) {
        // fork后子进程的pid
        t = waitpid(-1, &stat, __WALL | WUNTRACED);

        // 判断当前 fork 程序是不是我们指定的应用
        // if (t != 0 && t == child_pid) {
        if (t != 0){
            child_pid = t;
            if (debug > 1)
                printf(".");
            char fname[256];
            sprintf(fname, "/proc/%d/cmdline", child_pid);
            int fp = open(fname, O_RDONLY);
            if (fp < 0) {
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                continue;
            }
            read(fp, fname, sizeof(fname));
            close(fp);
            // -s 传进来的参数
            if (strcmp(fname, appname) == 0) {
				printf("匹配到appname: %s\n",appname);
                if (debug)
                    printf("zygote -> %s\n", fname);

                // detach from zygote
                ptrace(PTRACE_DETACH, pid, 0, (void *)SIGCONT);
				printf("Detach from zygote\n");

                // now perform on new process
                pid = child_pid;
				printf("appname: %s pid: %d\n",appname,pid);
                zygote = 1;
                break;
            } else {
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                continue;
            }
        }
    }
    // 获取到子进程pid
    if (zygote) {
            // 获取到指定进程pid后，拦截它的system_call
            res = ptrace(PTRACE_SYSCALL, pid, 0, 0);
            while (1) {
                waitpid(pid, NULL, 0);
				// edited by JC0o0l
				// long sysCallNo = getSys
				// end
                //系统调用前修改调用参数   
				//printf("系统调用前修改调用参数\n");
                hookSysCallBefore(pid,pid2);
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
    
                waitpid(pid, NULL, 0);
                // 修改系统调用结果
				//printf("系统调用后修改调用结果\n");
                hookSysCallAfter(pid);
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
            }
    }
    return 0;
}
void hookSysCallBefore(pid_t pid,pid_t pid2) {
    struct pt_regs regs;
    int sysCallNo = 0;
	struct {
		void* ufb;
		size_t len;
	} regsvec = {&regs,sizeof(struct pt_regs) };
 
	//ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regsvec);
    //sysCallNo = getSysCallNo(pid, &regs);
	sysCallNo = regs.regs[8];
	printf("\n\n===Before===\npid: %d call syscallNo: %d \n",pid,sysCallNo);
	printf("Before: argv[0]: %d\n",regs.regs[0]);
	printf("Before: argv[1]: 0x%x\n",regs.regs[1]);
	//printf("sysCallNo: %d\n",sysCallNo);
 	//printf("__NR_ptrace: %d\n",__NR_ptrace);
    //if (sysCallNo == __NR_ptrace) {
    if (sysCallNo == 260) {
		printf("ptrace系统调用\n");
		printf("Before: argv[2]: 0x%x\n",regs.regs[2]);
		printf("Before: argv[3]: 0x%x\n",regs.regs[3]);
		// test 
		regs.ARM_r0 = pid2;
		ptrace(PTRACE_SETREGSET,pid,NT_foo,&regsvec);
		// end
		sleep(6);
    }
}

void hookSysCallAfter(pid_t pid) {
    struct pt_regs regs;
    int sysCallNo = 0;
	struct {
		void* ufb;
		size_t len;
	} regsvec = {&regs,sizeof(struct pt_regs) };
 
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regsvec);
    //sysCallNo = getSysCallNo(pid, &regs);
	sysCallNo = regs.regs[8];
	printf("===After===\npid: %d call syscallNo: %d \n",pid,sysCallNo);
	printf("After: return Value: %d\n\n",regs.regs[0]); 
    if (sysCallNo == 260) {
		regs.ARM_r0 = 0;//PTRACE_PEEKTEXT;
		printf("修改后: return Value: %d\n\n",regs.regs[0]); 
		ptrace(PTRACE_SETREGSET,pid,NT_foo,&regsvec);
		sleep(6);
    }
    //if (sysCallNo == __NR_ptrace) {
}

long getSysCallNo(int pid,struct pt_regs* regs){
	//printf("获取syscallNo\n");
	long scno = 0;
	// edited by JC0o0l
	scno = regs->regs[8];
	
	printf("pid: %d call syscallNo: %d \n",pid,scno);
	return scno;
	// end
	//scno = ptrace(PTRACE_PEEKTEXT,pid,(void*)(regs->ARM_pc -4),NULL);
	//printf("scno: %d\n",scno);
	//if(scno == 0)
	//	return 0;
	//if (scno == 0xef000000){
	//	scno = regs->ARM_r7;
	//}else{
	//	if((scno & 0x0ff00000)!= 0x0f900000){
	//		return -1;
	//	}
	//	scno &= 0x000fffff;
	//}
	//return scno;
}
