 JC-AntiPtrace

**环境：NDK-r17c,ARM64,pixel2,Android 8.1**

目标：用于绕过ptrace反调试

进度：开发中...

Author: JC0o0l

# Version 1

JC-AntiPtrace-v1-arm64.c

具体信息见：https://www.freebuf.com/sectool/257766.html

## 适用场景

1. zygote通过fork()系统调用，fork出一个app
2. app内通过ptrace(PTRACE_TRACEME,0,0,0);将父进程zygote做为自己的tracer
3. 这样其他进程就无法ptrace()到app进程了

## 使用说明：

```shell
JC-AntiPtrace-v1-arm64.o [-v] -p <zygote_pid> -t <appname> [-n <syscallNo>] [-r<returnValue> [-e]]
options:
-v : verbose
-p <zygote_pid> : pid of zygote or zygote64
-t <appname> : application name of to hook
-n <syscallno> : syscalll number to hook(十进制)
    117:ptrace
    220:clone
    260:wait
-r<returnValue> : update return value of the syscallno
-h : show helper
-e : detach when updated return value
```

### (1)、用于监控系统调用

```shell
JC-AntiPtrace-v1-arm64.o [-v] -p <zygote_pid> -t <appname> [-n <syscallNo>]
-v: 表示显示详细输出，包含有每个系统调用的参数值与返回值
-p: 表示zygote进程的pid
-t: 要监控的app的名称
-n：表示监控某一个特定的系统调用
```

### (2)、用于绕过ptrace反调试

```shell
JC-AntiPtrace-v1-arm64.o [-v] -p <zygote_pid> -t <appname> [-n 117] [-r0 [-e]]
-v: 表示显示详细输出，包含有每个系统调用的参数值与返回值
-p: 表示zygote进程的pid
-t: 要监控的app的名称
-n：表示监控某一个特定的系统调用
-r: 表示要修改返回值为某个值。-r后面紧跟数值
-e: 表示修改返回值后就detach
```





# Version 2

JC-AntiPtrace-v2.c
