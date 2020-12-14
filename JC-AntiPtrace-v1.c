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
#include <getopt.h>

// Author: JC0o0l,Jerrybird
// WeChat: JC_SecNotes
// version: 1.0
//

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

void enterSysCall(pid_t pid);
int leaveSysCall(pid_t pid);
long getSysCallNo(int pid,struct pt_regs* regs);
int getCmdline(pid_t pid,char* des);
extern int errno;
int flag = 0;

void show_helper(){
	printf(
		"\n\nJC-AntiPtrace-v1.o [-v] -p <zygote_pid> -t <appname> [-n 117] [-r0 [-e]]\n"
		"options:\n"
		"\t-v : verbose\n"
		"\t-p <zygote_pid> : pid of zygote or zygote64\n"
		"\t-t <appname> : application name of to hook\n"
		"\t-n <syscallno> : syscalll number to hook(十进制)\n"
		"\t\t 117:ptrace\n"
		"\t\t 220:clone\n"
		"\t\t 260:wait\n"
		"\t-r<returnValue> : update return value of the syscallno\n"
		"\t-h : show helper\n"
		"\t-e : detach when updated return value\n"
					);
}
void show_banner(){
	printf(
"888888888888     88           ad88888ba                           \n"
"         ,88   ,d88          d8\"     \"8b                          \n"
"       ,88\"  888888          Y8,                                  \n"
"     ,88\"        88          `Y8aaaaa,     ,adPPYba,   ,adPPYba,  \n"
"   ,88\"          88  aaaaaaaa  `\"\"\"\"\"8b,  a8P_____88  a8\"     \"\"  \n"
" ,88\"            88  \"\"\"\"\"\"\"\"        `8b  8PP\"\"\"\"\"\"\"  8b          \n"
"88\"              88          Y8a     a8P  \"8b,   ,aa  \"8a,   ,aa  \n"
"888888888888     88           \"Y88888P\"    `\"Ybbd8\"'   `\"Ybbd8\"'  \n"
"\n\nTool: JC-AntiPtrace-v1.0\nAuthor: JC0o0l\nVersion: 1.0\nWeChat: JC_SecNotes\n"
		  );
}
int syscall_tohook = 117;
int return_tohook = -1;
int debug = -1;
int pid = -1;
char* appname;
int exit_tohook = -1;
int main(int argc,char* argv[]){
	// 命令行解析函数
	//
    // -d -p <pid> -t <appname>
	int opt;
	char* optString = "vp:t:hn:r::e";
	if (argc < 3){
		show_banner();
		show_helper();
		return 0;
	}
	show_banner();
	while((opt = getopt(argc,argv,optString))!= -1){
		if(opt == 'v'){
			debug = 11;
		}else if(opt == 'p'){
			pid = atoi(optarg);
		}else if(opt == 't'){
			appname = optarg;
		}else if(opt == 'h'){
			show_helper();
			return 0;
		}else if(opt == 'n'){
			syscall_tohook = atoi(optarg);
		}else if(opt == 'r'){
			return_tohook = atoi(optarg);
		}else if(opt == 'e'){
			exit_tohook = 1;
		}	
	}
	if(pid == -1){
		show_helper();
		return 0;
	}

    //int debug = atoi(argv[1]);
    //int pid = atoi(argv[2]);
    //char* appname = argv[3];
	printf("pid: %d\n",pid);
	printf("appname: %s\n",appname);
	// 附加到zygote进程
	int res = ptrace(PTRACE_ATTACH,pid,0,0);
	if(res == -1){
		printf("res: %d\n",res);
		printf("hook zygote error\n");
		show_helper();
		return -1;
	}
	// 等待附加完成
    waitpid(pid, NULL, 0);


    // 拦截 zygote 进程的 fork
	res = ptrace(PTRACE_SETOPTIONS, pid, (void *)0, (void *)(PTRACE_O_TRACEFORK));
	printf("res: %d\n",res);
    if (res == -1) {
        printf("FATAL ERROR: ptrace(PTRACE_SETOPTIONS, ...)\n");
		printf("errno: %d\n",errno);
        return -1;
    }
	// 让zygote恢复运行
    ptrace(PTRACE_CONT, pid, (void *)1, 0);
	int wait_pid;
    int stat;
    int zygote = 0;

    for (;;) {
        // fork后子进程的pid
        wait_pid = waitpid(-1, &stat, __WALL | WUNTRACED);

        // 判断fork后的程序是不是我们指定的应用
        if (wait_pid != 0){
            if (debug > 1)
                printf(".");
            char fname[256];
            sprintf(fname, "/proc/%d/cmdline", wait_pid);
            int fp = open(fname, O_RDONLY);
            if (fp < 0) {
				printf("fp < 0\n");
                ptrace(PTRACE_SYSCALL, wait_pid, 0, 0);
				//ptrace(PTRACE_SETOPTIONS, wait_pid, (void *)0, (void *)(PTRACE_O_TRACEFORK));
    			//ptrace(PTRACE_CONT, wait_pid, (void *)1, 0);
                continue;
            }
            read(fp, fname, sizeof(fname));
            close(fp);
            // -s 传进来的参数
            if (strcmp(fname, appname) == 0) {
				printf("匹配到appname: %s\n",appname);
                if (debug > -1)
                    printf("zygote -> %s\n", fname);
                // detach from zygote
                ptrace(PTRACE_DETACH, pid, 0, (void *)SIGCONT);
				printf("Detach from zygote\n");
                // now perform on new process
                pid = wait_pid;
				printf("appname: %s pid: %d\n",appname,pid);
                zygote = 1;
                break;
            } else {
				if(debug > -1){
					printf("Next fork,current app: %s\n",fname);
				}
                ptrace(PTRACE_SYSCALL, wait_pid, 0, 0);
			//	ptrace(PTRACE_SETOPTIONS, wait_pid, (void *)0, (void *)(PTRACE_O_TRACEFORK));
    		//	ptrace(PTRACE_CONT, wait_pid, (void *)1, 0);
                continue;
            }
        }
    }
	sleep(5);
    // 获取到子进程pid
    if (zygote) {
            // 获取到指定进程pid后，拦截它的system_call
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
    		//ptrace(PTRACE_CONT, pid, (void *)1, 0);
			pid_t new_pid;
            while (1) {
				flag = 0;
        		wait_pid = waitpid(pid, &stat, __WALL | WUNTRACED);
				if(WIFEXITED(stat)){
					printf("pid: %d,exited\n",pid);
					return 0;
				}
				if(debug > -1){
					printf("appname: %s,pid: %d,wait_pid: %d\n",appname,pid,wait_pid);
				}
				if(ptrace(PTRACE_GETEVENTMSG,wait_pid,0,&new_pid) == -1){
					printf("wait_pid: %d\n",wait_pid);
					printf("new_pid: %d\n",new_pid);
					printf("errno: %d\n",errno);
					printf("ptrace geteventmsg error\n");
					continue;
				}
				//printf("系统调用前修改调用参数\n");
                enterSysCall(pid);
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                waitpid(pid, NULL, 0);
                // 修改系统调用结果
				//printf("系统调用后修改调用结果\n");
                pid_t tmp = leaveSysCall(pid);
				if(flag == 0)
	                ptrace(PTRACE_SYSCALL, pid, 0, 0);
				if(exit_tohook == 1 && flag == 1)
				{
            		ptrace(PTRACE_DETACH, pid, 0, (void *)SIGCONT);
	                //ptrace(PTRACE_SYSCALL, tmp, 0, 0);
					printf("detach from %s\n",appname);
					return 0;
				}
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
            }
    }
    return 0;
}
int getCmdline(pid_t pid,char* fname){
    sprintf(fname, "/proc/%d/cmdline", pid);
    int fp = open(fname, O_RDONLY);
    if (fp < 0) {
			printf("get cmdline:pid: %d, errorno: %d\n",pid,errno);
			return -1;
    }
    read(fp, fname, sizeof(fname));
    close(fp);
	//printf("%s\n",fname);
	return 0;

}
void enterSysCall(pid_t pid) {
    struct pt_regs regs;
    int sysCallNo = 0;
	struct {
		void* ufb;
		size_t len;
	} regsvec = {&regs,sizeof(struct pt_regs) };
 
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regsvec);
	sysCallNo = regs.regs[8];
	// clone: 220
	// wait4: 260
	// ptrace: 117
	if(debug > -1){
		printf("\n\n===Enter Syscall===\npid: %d call syscallNo: %d \n",pid,sysCallNo);
		printf("Before: argv[0]: %d\n",regs.regs[0]);
		printf("Before: argv[1]: 0x%x\n",regs.regs[1]);
		printf("Before: argv[2]: 0x%x\n",regs.regs[2]);
		printf("Before: argv[3]: 0x%x\n",regs.regs[3]);
	}else if(sysCallNo == syscall_tohook){
		printf("\n\n===Enter Syscall===\npid: %d call syscallNo: %d \n",pid,sysCallNo);
		printf("Before: argv[0]: %d\n",regs.regs[0]);
		printf("Before: argv[1]: 0x%x\n",regs.regs[1]);
		printf("Before: argv[2]: 0x%x\n",regs.regs[2]);
		printf("Before: argv[3]: 0x%x\n",regs.regs[3]);
	}
}
int leaveSysCall(pid_t pid) {
    struct pt_regs regs;
    int sysCallNo = 0;
	struct {
		void* ufb;
		size_t len;
	} regsvec = {&regs,sizeof(struct pt_regs) };
 
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regsvec);
	sysCallNo = regs.regs[8];
	if(debug > -1){
		printf("===Leave Syscall===\npid: %d call syscallNo: %d \n",pid,sysCallNo);
		printf("Leave: return Value: %d\n\n",regs.regs[0]); 
		printf("Leave: argv[1]: 0x%x\n",regs.regs[1]);
		printf("Leave: argv[2]: 0x%x\n",regs.regs[2]);
		printf("Leave: argv[3]: 0x%x\n",regs.regs[3]);
		if(sysCallNo == syscall_tohook && return_tohook != -1){
			// 修改返回值
			regs.regs[0] = return_tohook;
			ptrace(PTRACE_SETREGSET,pid,NT_PRSTATUS,&regsvec);
			printf("update: return Value: %d\n\n",regs.regs[0]); 
			flag = 1;
		}
	}else if(sysCallNo == syscall_tohook){
		printf("===Leave Syscall===\npid: %d call syscallNo: %d \n",pid,sysCallNo);
		printf("Leave: return Value: %d\n\n",regs.regs[0]); 
		if(return_tohook != -1){
			// 修改返回值
			regs.regs[0] = return_tohook;
			ptrace(PTRACE_SETREGSET,pid,NT_PRSTATUS,&regsvec);
			printf("update: return Value: %d\n\n",regs.regs[0]); 
			flag = 1;
		}
	}
	return regs.regs[0];
}

long getSysCallNo(int pid,struct pt_regs* regs){
	//printf("获取syscallNo\n");
	long scno = 0;
	// edited by JC0o0l
	scno = regs->regs[8];
	
	printf("pid: %d call syscallNo: %d \n",pid,scno);
	return scno;
}
