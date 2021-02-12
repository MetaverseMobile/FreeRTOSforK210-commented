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
#include <FreeRTOS.h>
#include <task.h>
#include <sleep.h>
#include <sysctl.h>



/* 纳秒级休眠 */
int nanosleep(const struct timespec* req, struct timespec* rem)
{
    /* 秒转换为毫秒 */
    uint64_t clock_sleep_ms = (uint64_t)req->tv_sec * 1000;
    /* 纳秒转换为毫秒 */
    uint64_t nsec_ms = req->tv_nsec / 1000000;
    /* 转换过程丢失的精度 */
    uint64_t nsec_trailing = req->tv_nsec % 1000000;

    /* 休眠总毫秒数 */
    clock_sleep_ms += nsec_ms;

    /* 使得任务休眠 clock_sleep_ms 毫秒 */
    if (clock_sleep_ms)
        vTaskDelay(pdMS_TO_TICKS(clock_sleep_ms));


    /* 剩下的微秒数将会通过系统时钟计数实现 */
    uint64_t microsecs = nsec_trailing / 1000;
    if (microsecs)
    {
        /* 求得 CPU 的每个微秒执行的指令周期 */
        uint32_t cycles_per_microsec = sysctl_clock_get_freq(SYSCTL_CLOCK_CPU) / 3000000;
        while (microsecs--)
        {
            /* 此处利用空转实现休眠，故频繁使用 nanosleep 其实也会对实时性产生影响 */
            int i = cycles_per_microsec;
            while (i--)
                asm volatile("nop");
        }
    }

    return 0;
}


/* 微妙级休眠 */
int usleep(useconds_t usec)
{
    /* 转换为 结构体形式，调用通过 nanosleep 实现 */
    struct timespec req =
    {
        .tv_sec = 0,
        .tv_nsec = usec * 1000
    };

    return nanosleep(&req, (struct timespec*)0x0);
}



/* 秒级休眠 */
unsigned int sleep(unsigned int seconds)
{
    /* clang-format off */
    /* 转换为 结构体形式，调用通过 nanosleep 实现 */
    struct timespec req =
    {
        .tv_sec = seconds,
        .tv_nsec = 0
    };

    return (unsigned int)nanosleep(&req, (struct timespec*)0x0);
}
