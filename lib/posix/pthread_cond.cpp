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
#include "utils.h"
#include <FreeRTOS.h>
#include <atomic>
#include <climits>
#include <cstring>
#include <errno.h>
#include <kernel/driver_impl.hpp>
#include <platform.h>
#include <pthread.h>
#include <semphr.h>
#include <task.h>

using namespace sys;



static const pthread_condattr_t s_default_cond_attributes = {
    .is_initialized = true,
    .clock = portMAX_DELAY
};


/* 内核可见 posix 线程库 条件变量 */
struct k_pthread_cond
{
    /* 锁 */
    StaticSemaphore_t mutex;
    StaticSemaphore_t wait_semphr;
    uint32_t waiting_threads;

    /* 构造函数
     * 等待进程数初始化为 0, 并初始化锁 */
    k_pthread_cond() noexcept
        : waiting_threads(0)
    {
        xSemaphoreCreateMutexStatic(&mutex);
        xSemaphoreCreateCountingStatic(UINT_MAX, 0U, &wait_semphr);
    }

    /* 析构函数 等待锁释放 和 等待队列为空 */
    ~k_pthread_cond()
    {
        vSemaphoreDelete(&mutex);
        vSemaphoreDelete(&wait_semphr);
    }

    /* 取得锁 */
    semaphore_lock lock() noexcept
    {
        return { &mutex };
    }

    /* 解除等待 */
    void give() noexcept
    {
        xSemaphoreGive(&wait_semphr);
        waiting_threads--;
    }
};




static void pthread_cond_init_if_static(pthread_cond_t *cond)
{
    if (*cond == PTHREAD_COND_INITIALIZER)
    {
        configASSERT(pthread_cond_init(cond, nullptr) == 0);
    }
}

/* 初始化条件变量属性 */
int pthread_condattr_init(pthread_condattr_t *__attr)
{
    *__attr = s_default_cond_attributes;
    return 0;
}

/* 销毁环境变量属性 */
int pthread_condattr_destroy(pthread_condattr_t *__attr)
{
    __attr->is_initialized = false;
    return 0;
}


/* 时钟属性控制计算pthread_cond_timewait函数的超时参数（tsptr）时采用的是哪个时钟合法值取自下图列出的时钟ID */
/* pthread_cond_timedwait函数使用前需要用pthread_condattr_t对条件变量进行初始化*/

/* 此函数获取可被用于pthread_cond_timedwait函数的时钟ID */
int pthread_condattr_getclock(const pthread_condattr_t *__attr, clockid_t *__clock_id)
{
    *__clock_id = __attr->clock;
    return 0;
}

/* 此函数用于设置pthread_cond_timewait函数使用的时钟ID */
int pthread_condattr_setclock(pthread_condattr_t *__attr, clockid_t __clock_id)
{
    __attr->clock = __clock_id;
    return 0;
}

/* 设置条件变量的进程共享属性 */
int pthread_condattr_getpshared(const pthread_condattr_t *__attr, int *__pshared)
{
    *__pshared = 1;
    return 0;
}

/* 获取条件变量的进程共享属性 */
int pthread_condattr_setpshared(pthread_condattr_t *__attr, int __pshared)
{
    return 0;
}


/* 初始化条件变量 */
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
    int iStatus = 0;
    k_pthread_cond *k_cond = nullptr;

    /* Silence warnings about unused parameters. */
    (void)attr;

    k_cond = new (std::nothrow) k_pthread_cond();

    if (!k_cond)
    {
        iStatus = ENOMEM;
    }

    if (iStatus == 0)
    {
        /* Set the output. */
        *cond = reinterpret_cast<uintptr_t>(k_cond);
    }

    return iStatus;
}

/* 销毁条件变量 */
int pthread_cond_destroy(pthread_cond_t *cond)
{
    k_pthread_cond *k_cond = reinterpret_cast<k_pthread_cond *>(*cond);

    delete k_cond;
    return 0;
}


/* 进入等待 */
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    return pthread_cond_timedwait(cond, mutex, NULL);
}


/* 向等待队列中至少 1 个任务发送信号 */
int pthread_cond_signal(pthread_cond_t *cond)
{
    /* 取得有效的 条件变量对象 */
    pthread_cond_init_if_static(cond);
    k_pthread_cond *k_cond = reinterpret_cast<k_pthread_cond *>(*cond);

    /* Check that at least one thread is waiting for a signal. */
    /* 存在等待信号的队列 */
    if (k_cond->waiting_threads)
    {
        /* Lock xCondMutex to protect access to iWaitingThreads.
         * This call will never fail because it blocks forever. */
        auto lock = k_cond->lock();
        /* 令对象持有锁 */
        xSemaphoreTake(&k_cond->mutex, portMAX_DELAY);

        /* Check again that at least one thread is waiting for a signal after
         * taking xCondMutex. If so, unblock it. */
        /* 解除等待 */
        if (k_cond->waiting_threads)
            k_cond->give();
    }

    return 0;
}


/* 条件变量计时等待 */
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime)
{
    int iStatus = 0;

    /* 检查变量是否静态初始化 */
    pthread_cond_init_if_static(cond);

    /* 转换为内核可以解释的模式 */
    k_pthread_cond *k_cond = reinterpret_cast<k_pthread_cond *>(*cond);

    /* Convert abstime to a delay in TickType_t if provided. */
    /* 将时间转换为时钟周期数, 如果未空, 则改为永久 */
    TickType_t xDelay = portMAX_DELAY;
    if (abstime != NULL)
        xDelay = timespec_to_ticks(*abstime);

    /* Increase the counter of threads blocking on condition variable, then
     * unlock mutex. */
    if (iStatus == 0)
    {
        {
            /* 拿到锁 */
            auto lock = k_cond->lock();
            /* 当前信号量等待线程数 + 1 */
            k_cond->waiting_threads++;
        }

        /* 先释放锁 */
        iStatus = pthread_mutex_unlock(mutex);
    }

    /* Wait on the condition variable. */
    if (iStatus == 0)
    {
        /* 进入休眠 */
        if (xSemaphoreTake(&k_cond->wait_semphr, xDelay) == pdPASS)
        {
            /* When successful, relock mutex. */
            /* 唤醒时, 立刻持有锁 ———— 这里不需要保证原子性 ???? */
            iStatus = pthread_mutex_lock(mutex);
            /* 不需要减少等待线程数? */
        }
        else
        {
            /* Timeout. Relock mutex and decrement number of waiting threads. */
            iStatus = ETIMEDOUT;
            /* 超时后再次持有锁, 并将等待队列的线程 -1 */
            (void)pthread_mutex_lock(mutex);

            {
                auto lock = k_cond->lock();
                /* 等待线程数 - 1 */
                k_cond->waiting_threads--;
            }
        }
    }

    return iStatus;
}


/* 向等待该信号的所有任务发送唤醒信号 */
int pthread_cond_broadcast(pthread_cond_t *cond)
{
    int i = 0;
    pthread_cond_init_if_static(cond);
    k_pthread_cond *k_cond = reinterpret_cast<k_pthread_cond *>(*cond);

    /* Lock xCondMutex to protect access to iWaitingThreads.
     * This call will never fail because it blocks forever. */
    auto locker = k_cond->lock();

    /* Unblock all threads waiting on this condition variable. */
    for (i = 0; i < k_cond->waiting_threads; i++)
    {
        xSemaphoreGive(&k_cond->wait_semphr);
    }

    /* All threads were unblocked, set waiting threads to 0. */
    k_cond->waiting_threads = 0;

    return 0;
}
