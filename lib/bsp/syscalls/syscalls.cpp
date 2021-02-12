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
#include "syscalls.h"
#include <devices.h>
#include <filesystem.h>
#include <kernel/driver_impl.hpp>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>

using namespace sys;


/* open 系统调用 */
int sys_open(const char *name, int flags, int mode)
{

    handle_t handle = NULL_HANDLE;
    /* 如果路径指向硬件或虚拟设备 */
    if (strstr(name, "/dev/") != NULL)
    {
        /* 调用 io_open —————— 权限和标志失效 */
        handle = io_open(name);
    }
    /* 如果路径指向文件系统 */
    else if (strstr(name, "/fs/") != NULL)
    {
        /* 解析文件权限 */
        file_access_t file_access = FILE_ACCESS_READ;
        /* 写 */
        if (flags & O_WRONLY)
            file_access = FILE_ACCESS_WRITE;
        /* 读 */
        else if (flags & O_RDWR)
            file_access = FILE_ACCESS_READ_WRITE;

        /* 解析打开方式 */
        file_mode_t file_mode = FILE_MODE_OPEN_EXISTING;
        /*  创建文件 */
        if (flags & O_CREAT)
            file_mode |= FILE_MODE_CREATE_ALWAYS;
        /* 增量写入 */
        if (flags & O_APPEND)
            file_mode |= FILE_MODE_APPEND;
        /* 不做分割 */
        if (flags & O_TRUNC)
            file_mode |= FILE_MODE_TRUNCATE;
        /* 读取文件 */
        handle = filesystem_file_open(name, file_access, file_mode);
    }

    if (handle)
        return handle;
    return -1;
}


/* 文件读取指针跳转 */
off_t sys_lseek(int fd, off_t offset, int whence)
{
    /* 不允许对标准输入输出设备进行读取跳转 */
    if (STDOUT_FILENO == fd || STDERR_FILENO == fd)
        return -1;

    try
    {
        /* 通过描述符得到相应的对象 */
        auto &obj = system_handle_to_object(fd);
        if (auto f = obj.as<filesystem_file>())
        {
            /* 移动文件指针 */
            if (whence == SEEK_SET)
            {
                f->set_position(offset);
            }
            else if (whence == SEEK_CUR)
            {
                auto pos = f->get_position();
                f->set_position(pos + offset);
            }
            else if (whence == SEEK_END)
            {
                auto pos = f->get_size();
                f->set_position(pos - offset);
            }

            return f->get_position();
        }

        return -1;
    }
    catch (...)
    {
        return -1;
    }
}


/* 获取文件状态 */
int sys_fstat(int fd, struct kernel_stat *buf)
{
    /* 不允许获取标准输出和出错设备的文件状态 */
    if (STDOUT_FILENO == fd || STDERR_FILENO == fd)
        return 0;

    try
    {
        /* 该调用会为用户进行初始化 */
        memset(buf, 0, sizeof(struct kernel_stat));
        /* 通过描述符取得文件对象 */
        auto &obj = system_handle_to_object(fd);
        if (auto f = obj.as<filesystem_file>())
        {
            /* 只返回文件大小 */
            buf->st_size = f->get_size();
            return 0;
        }

        return -1;
    }
    catch (...)
    {
        return -1;
    }
}
