/* Copyright 2018 Canaan Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "syscalls/syscalls.h"
#include <atomic.h>
#include <clint.h>
#include <devices.h>
#include <dump.h>
#include <errno.h>
#include <filesystem.h>
#include <fpioa.h>
#include <interrupt.h>
#include <limits.h>
#include <machine/syscall.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <sysctl.h>
#include <syslog.h>
#include <uarths.h>

/*
 * @note       System call list
 *
 * See also riscv-newlib/libgloss/riscv/syscalls.c
 *
 * | System call      | Number |
 * |------------------|--------|
 * | SYS_exit         | 93     |
 * | SYS_exit_group   | 94     |
 * | SYS_getpid       | 172    |
 * | SYS_kill         | 129    |
 * | SYS_read         | 63     |
 * | SYS_write        | 64     |
 * | SYS_open         | 1024   |
 * | SYS_openat       | 56     |
 * | SYS_close        | 57     |
 * | SYS_lseek        | 62     |
 * | SYS_brk          | 214    |
 * | SYS_link         | 1025   |
 * | SYS_unlink       | 1026   |
 * | SYS_mkdir        | 1030   |
 * | SYS_chdir        | 49     |
 * | SYS_getcwd       | 17     |
 * | SYS_stat         | 1038   |
 * | SYS_fstat        | 80     |
 * | SYS_lstat        | 1039   |
 * | SYS_fstatat      | 79     |
 * | SYS_access       | 1033   |
 * | SYS_faccessat    | 48     |
 * | SYS_pread        | 67     |
 * | SYS_pwrite       | 68     |
 * | SYS_uname        | 160    |
 * | SYS_getuid       | 174    |
 * | SYS_geteuid      | 175    |
 * | SYS_getgid       | 176    |
 * | SYS_getegid      | 177    |
 * | SYS_mmap         | 222    |
 * | SYS_munmap       | 215    |
 * | SYS_mremap       | 216    |
 * | SYS_time         | 1062   |
 * | SYS_getmainvars  | 2011   |
 * | SYS_rt_sigaction | 134    |
 * | SYS_writev       | 66     |
 * | SYS_gettimeofday | 169    |
 * | SYS_times        | 153    |
 * | SYS_fcntl        | 25     |
 * | SYS_getdents     | 61     |
 * | SYS_dup          | 23     |
 *
 */



#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif


/* 返回系统调用结果 */
#define SYS_RET(epc_val, err_val) \
    syscall_ret_t ret = {         \
        .err = err_val,           \
        .epc = epc_val            \
    };                            \
    return ret;


typedef struct _syscall_ret
{
    uintptr_t err;
    uintptr_t epc;
} syscall_ret_t;



static const char *TAG = "SYSCALL";

/* 堆起始地址 */
extern char _heap_start[];
/* 堆结尾 ———— 可 malloc 动态申请内存的最大边界 */
extern char _heap_end[];

/* 默认情况 堆的当前上界 位于 堆的起始位置 ———— 即不申请内存 */
char *_heap_cur = &_heap_start[0];


/* 退出系统 ———— 内核进入空转 */
void __attribute__((noreturn)) sys_exit(int code)
{
    /* First print some diagnostic information. */
    LOGW(TAG, "sys_exit called with 0x%lx\n", (uint64_t)code);
    while (1)
        ;
}


/* 不存在的系统调用 */
static int sys_nosys(long a0, long a1, long a2, long a3, long a4, long a5, unsigned long n)
{
    UNUSED(a3);
    UNUSED(a4);
    UNUSED(a5);

    return -ENOSYS;
}


/* 调用成功 */
static int sys_success(void)
{
    return 0;
}


/* sys_brk 用于管理堆内存 */
static size_t sys_brk(size_t pos)
{
    uintptr_t res = 0;
    /**
     * 
     * brk() 会把数据段的末端设置为特定地址, 当该输入地址有效时, 代表
     * 系统有足够当内存，并且该过程不超出当前数据类型的最大值；
     * 
     * sbrk() 将数据地址空间增大指定的值。当输入值为 0 当时候可以用于寻找
     * 当前 program break 的地址。
     * 
     * uintptr_t brk(uintptr_t ptr);
     *
     * IN : regs[10] = ptr
     * OUT: regs[10] = ptr
     */

    /**
     * 第一次调用会初始化 brk 指针, newlib 会传递 ptr = 0。该情况下会
     * 返回 _heap_start。
     *
     * 后续调用: 调整 brk 指针, ptr 永远不为 0，如果 ptr 小于 _heap_end,
     * 系统就会申请内存。否则抛出内存错误, 返回 -1。
     */

    if (pos)
    {
        /* 后续调用 */
        if ((uintptr_t)pos > (uintptr_t)&_heap_end[0])
        {
            res = -ENOMEM;
        }
        else
        {
            /* 申请的目标地址小于堆边界，则申请内存 */
            /* 调整 brk 指针的目标 */
            _heap_cur = (char *)(uintptr_t)pos;
            /* 返回新的堆顶 */
            res = (uintptr_t)_heap_cur;
        }
    }
    else
    {
        /* 第一次调用时, 返回 _heap_start */
        res = (uintptr_t)&_heap_start[0];
    }
    return (size_t)res;
}





/* *******************************
 * write 系统调用:
 * int file : 设备描述符
 * const void *ptr : 输出内容头指针
 * size_t len : 输出数据字节数
 * 
 * return : 返回输出的数据的字节数
 * *******************************/
static ssize_t sys_write(int file, const void *ptr, size_t len)
{
    /*
     * Write to a file.
     *
     * ssize_t write(int file, const void* ptr, size_t len)
     *
     * IN : regs[10] = file, regs[11] = ptr, regs[12] = len
     * OUT: regs[10] = len
     */

    ssize_t res = -EBADF;
    /* Get size to write */
    size_t length = len;
    /* Get data pointer */
    const uint8_t *data = (const uint8_t *)ptr;

    /* 如果目标设备是 标准输出或者标准出错 */
    if (STDOUT_FILENO == file || STDERR_FILENO == file)
    {
        /* Write data */
        while (length--)
            /* 用 高速 uart 输出数据 */
            uarths_write_byte(*data++);


        /* 返回输出的字节数 */
        /* 此处应该返回 len - length 才对 */
        res = len;
    }
    else
    {
        /* 如果不是标准输入输出设备, 调用 io_write */
        res = io_write(file, data, length);
    }

    return res;
}


/* *******************************
 * read 系统调用:
 * int file : 设备描述符
 * const void *ptr : 读取内容缓冲区
 * size_t len : 读取数据字节数
 * 
 * return : 返回输出的数据的字节数
 * *******************************/
static ssize_t sys_read(int file, void *ptr, size_t len)
{
    ssize_t res = -EBADF;

    /* 如果设备是标准输入 */
    if (STDIN_FILENO == file)
    {
        /* 直接从 uarths 缓冲中读取 */
        return uarths_read((uint8_t *)ptr, len);
    }
    else
    {
        /* 如果是其他描述符, 调用更为一般的 io_read */
        res = io_read(file, (uint8_t *)ptr, len);
    }

    return res;
}



static int sys_close(int file)
{
    /*
     * Close a file.
     *
     * int close(int file)
     *
     * IN : regs[10] = file
     * OUT: regs[10] = Upon successful completion, 0 shall be
     * returned.
     * Otherwise, -1 shall be returned and errno set to indicate
     * the error.
     */
    /* FreeRTOS 不允许关闭标准输出标准出错设备 */
    if (STDOUT_FILENO == file || STDERR_FILENO == file)
    {
        return 0;
    }
    else
    {
        /* 关闭设备 */
        return io_close(file);
    }
}

static int sys_gettimeofday(struct timeval *tp, void *tzp)
{
    /*
     * Get the current time.  Only relatively correct.
     *
     * int gettimeofday(struct timeval* tp, void* tzp)
     *
     * IN : regs[10] = tp
     * OUT: regs[10] = Upon successful completion, 0 shall be
     * returned.
     * Otherwise, -1 shall be returned and errno set to indicate
     * the error.
     */
    UNUSED(tzp);

    if (tp != NULL)
    {
        uint64_t clint_usec = clint->mtime * CLINT_CLOCK_DIV / (sysctl_clock_get_freq(SYSCTL_CLOCK_CPU) / 1000000UL);

        tp->tv_sec = clint_usec / 1000000UL;
        tp->tv_usec = clint_usec % 1000000UL;
    }
    /* Return the result */
    return 0;
}

static syscall_ret_t handle_ecall(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t epc, uintptr_t n)
{
    enum syscall_id_e
    {
        SYS_ID_NOSYS,
        SYS_ID_SUCCESS,
        SYS_ID_EXIT,
        SYS_ID_BRK,
        SYS_ID_READ,
        SYS_ID_WRITE,
        SYS_ID_OPEN,
        SYS_ID_FSTAT,
        SYS_ID_CLOSE,
        SYS_ID_GETTIMEOFDAY,
        SYS_ID_LSEEK,
        SYS_ID_MAX
    };

    /* 初始化系统调用函数入口组成的函数数组 */
    static uintptr_t (*const syscall_table[])(long a0, long a1, long a2, long a3, long a4, long a5, unsigned long n) = {
        [SYS_ID_NOSYS] = (void *)sys_nosys,
        [SYS_ID_SUCCESS] = (void *)sys_success,
        [SYS_ID_EXIT] = (void *)sys_exit,
        [SYS_ID_BRK] = (void *)sys_brk,
        [SYS_ID_READ] = (void *)sys_read,
        [SYS_ID_WRITE] = (void *)sys_write,
        [SYS_ID_OPEN] = (void *)sys_open,
        [SYS_ID_FSTAT] = (void *)sys_fstat,
        [SYS_ID_CLOSE] = (void *)sys_close,
        [SYS_ID_GETTIMEOFDAY] = (void *)sys_gettimeofday,
        [SYS_ID_LSEEK] = (void *)sys_lseek,
    };

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Woverride-init"
#endif
    /* 批量初始化系统调用表 */
    /* [5] = 100 相当于 syscall_id_table[5] = 100 */
    static const uint8_t syscall_id_table[0x100] = {
        [0x00 ... 0xFF] = SYS_ID_NOSYS,
        [0xFF & SYS_exit] = SYS_ID_EXIT,
        [0xFF & SYS_exit_group] = SYS_ID_EXIT,
        [0xFF & SYS_getpid] = SYS_ID_NOSYS,
        [0xFF & SYS_kill] = SYS_ID_NOSYS,
        [0xFF & SYS_read] = SYS_ID_READ,
        [0xFF & SYS_write] = SYS_ID_WRITE,
        [0xFF & SYS_open] = SYS_ID_OPEN,
        [0xFF & SYS_openat] = SYS_ID_NOSYS,
        [0xFF & SYS_close] = SYS_ID_CLOSE,
        [0xFF & SYS_lseek] = SYS_ID_LSEEK,
        [0xFF & SYS_brk] = SYS_ID_BRK,
        [0xFF & SYS_link] = SYS_ID_NOSYS,
        [0xFF & SYS_unlink] = SYS_ID_NOSYS,
        [0xFF & SYS_mkdir] = SYS_ID_NOSYS,
        [0xFF & SYS_chdir] = SYS_ID_NOSYS,
        [0xFF & SYS_getcwd] = SYS_ID_NOSYS,
        [0xFF & SYS_stat] = SYS_ID_NOSYS,
        [0xFF & SYS_fstat] = SYS_ID_FSTAT,
        [0xFF & SYS_lstat] = SYS_ID_NOSYS,
        [0xFF & SYS_fstatat] = SYS_ID_NOSYS,
        [0xFF & SYS_access] = SYS_ID_NOSYS,
        [0xFF & SYS_faccessat] = SYS_ID_NOSYS,
        [0xFF & SYS_pread] = SYS_ID_NOSYS,
        [0xFF & SYS_pwrite] = SYS_ID_NOSYS,
        [0xFF & SYS_uname] = SYS_ID_NOSYS,
        [0xFF & SYS_getuid] = SYS_ID_NOSYS,
        [0xFF & SYS_geteuid] = SYS_ID_NOSYS,
        [0xFF & SYS_getgid] = SYS_ID_NOSYS,
        [0xFF & SYS_getegid] = SYS_ID_NOSYS,
        [0xFF & SYS_mmap] = SYS_ID_NOSYS,
        [0xFF & SYS_munmap] = SYS_ID_NOSYS,
        [0xFF & SYS_mremap] = SYS_ID_NOSYS,
        [0xFF & SYS_time] = SYS_ID_NOSYS,
        [0xFF & SYS_getmainvars] = SYS_ID_NOSYS,
        [0xFF & SYS_rt_sigaction] = SYS_ID_NOSYS,
        [0xFF & SYS_writev] = SYS_ID_NOSYS,
        [0xFF & SYS_gettimeofday] = SYS_ID_GETTIMEOFDAY,
        [0xFF & SYS_times] = SYS_ID_NOSYS,
        [0xFF & SYS_fcntl] = SYS_ID_NOSYS,
        [0xFF & SYS_getdents] = SYS_ID_NOSYS,
        [0xFF & SYS_dup] = SYS_ID_NOSYS,
    };
#if defined(__GNUC__)
#pragma GCC diagnostic warning "-Woverride-init"
#endif

    /* 查表并进行系统调用 */
    uintptr_t err = syscall_table[syscall_id_table[0xFF & n]](
        a0, /* a0 */
        a1, /* a1 */
        a2, /* a2 */
        a3, /* a3 */
        a4, /* a4 */
        a5, /* a5 */
        n /* n */
    );

    epc += 4;
    SYS_RET(epc, err);
}



syscall_ret_t __attribute__((weak, alias("handle_ecall")))
handle_ecall_u(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t epc, uintptr_t n);

syscall_ret_t __attribute__((weak, alias("handle_ecall")))
handle_ecall_h(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t epc, uintptr_t n);

syscall_ret_t __attribute__((weak, alias("handle_ecall")))
handle_ecall_s(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t epc, uintptr_t n);

syscall_ret_t __attribute__((weak, alias("handle_ecall")))
handle_ecall_m(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t epc, uintptr_t n);


/* 处理系统调用 */
syscall_ret_t handle_syscall(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t epc, uintptr_t n)
{
    /* 系统调用异常处理表 */
    static syscall_ret_t (*const cause_table[])(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t epc, uintptr_t n) = {
        [CAUSE_USER_ECALL] = handle_ecall_u,
        [CAUSE_SUPERVISOR_ECALL] = handle_ecall_h,
        [CAUSE_HYPERVISOR_ECALL] = handle_ecall_s,
        [CAUSE_MACHINE_ECALL] = handle_ecall_m,
    };

    return cause_table[read_csr(mcause)](a0, a1, a2, a3, a4, a5, epc, n);
}
