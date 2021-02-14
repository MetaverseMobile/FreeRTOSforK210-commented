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
#include <cstring>
#include <errno.h>
#include <memory>
#include <platform.h>
#include <pthread.h>
#include <semphr.h>
#include <task.h>


/* mutex 属性 */
static const pthread_mutexattr_t s_default_mutex_attributes = {
    /* 初始化过 */
    .is_initialized = true,
    /* mutex 类型 */
    .type = PTHREAD_MUTEX_DEFAULT,
    /* 可重复上锁的次数 */
    .recursive = 0
};



/* 内核 mutex 类 */
struct k_pthread_mutex
{
    /* 属性 */
    pthread_mutexattr_t attr;
    /* 信号量 */
    StaticSemaphore_t semphr;
    /* 持有锁的线程 */
    TaskHandle_t owner;

    /* 构造函数 */
    k_pthread_mutex(pthread_mutexattr_t attr) noexcept
        : attr(attr)
    {
        if (attr.type == PTHREAD_MUTEX_RECURSIVE)
            /* 可重复上锁 */
            xSemaphoreCreateRecursiveMutexStatic(&semphr);
        else
            /* 不可重复上锁 */
            xSemaphoreCreateMutexStatic(&semphr);
    }

    /* 释放锁 */
    void give() noexcept
    {
        if (attr.type == PTHREAD_MUTEX_RECURSIVE)
            /* 可重复上锁 */
            xSemaphoreGiveRecursive(&semphr);
        else
            /* 不可重复上锁 */
            xSemaphoreGive(&semphr);
    }

    /* 改变锁的持有者 */
    void update_owner() noexcept
    {
        /* 改变锁的持有者 */
        owner = xSemaphoreGetMutexHolder(&semphr);
    }
};


/* ????? */
static void pthread_mutex_init_if_static(pthread_mutex_t *mutex)
{
    if (*mutex == PTHREAD_MUTEX_INITIALIZER)
    {
        configASSERT(pthread_mutex_init(mutex, nullptr) == 0);
    }
}


/* 用默认属性初始化锁的属性 */
int pthread_mutexattr_init(pthread_mutexattr_t *__attr)
{
    *__attr = s_default_mutex_attributes;
    return 0;
}

/* 删除属性 */
int pthread_mutexattr_destroy(pthread_mutexattr_t *__attr)
{
    __attr->is_initialized = false;
    return 0;
}

/* 是否可以进程间共享 */
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *__attr, int *__pshared)
{
    *__pshared = 1;
    return 0;
}


/* 设置进程间共享属性 */
int pthread_mutexattr_setpshared(pthread_mutexattr_t *__attr, int __pshared)
{
    return 0;
}


/* 当前 mutex 类型 */
int pthread_mutexattr_gettype(const pthread_mutexattr_t * __attr, int *__kind)
{
    *__kind = __attr->type;
    return 0;
}


/* 设置 mutex 类型 */
int pthread_mutexattr_settype(pthread_mutexattr_t * __attr, int __kind)
{
    __attr->type = __kind;
    return 0;
}


/* 初始化 mutex */
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
    int iStatus = 0;
    k_pthread_mutex *k_mutex = nullptr;

    /* 实例化一个 kernel mutex 对象, 如果属性缺省, 则使用默认属性 */
    k_mutex = new (std::nothrow) k_pthread_mutex(attr ? *attr : s_default_mutex_attributes);

    if (!k_mutex)
    {
        iStatus = ENOMEM;
    }

    if (iStatus == 0)
    {
        /* 将内核的 mutex 暴露给用户 */
        *mutex = reinterpret_cast<uintptr_t>(k_mutex);
    }

    return iStatus;
}


/* 删除互斥锁 */
int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    /* 内核解析 mutex 对象 */
    k_pthread_mutex *k_mutex = reinterpret_cast<k_pthread_mutex *>(*mutex);

    /* Free resources in use by the mutex. */
    if (k_mutex->owner == NULL)
    {
        /* 释放对象 */
        delete k_mutex;
    }

    return 0;
}

/* 上锁 */
int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    return pthread_mutex_timedlock(mutex, NULL);
}


/* 定时上锁 */
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abstime)
{
    pthread_mutex_init_if_static(mutex);

    int iStatus = 0;
    k_pthread_mutex *k_mutex = reinterpret_cast<k_pthread_mutex *>(*mutex);
    TickType_t xDelay = portMAX_DELAY;
    BaseType_t xFreeRTOSMutexTakeStatus = pdFALSE;

    /* Convert abstime to a delay in TickType_t if provided. */
    /* 将时间转换为时钟数 */
    if (abstime != NULL)
        xDelay = timespec_to_ticks(*abstime);

    /* Check if trying to lock a currently owned mutex. */
    /* 指定 PTHREAD_MUTEX_ERRORCHECK 时, 检查当前线程是否已经持有锁 */
    if ((iStatus == 0) && (k_mutex->attr.type == PTHREAD_MUTEX_ERRORCHECK) && /* Only PTHREAD_MUTEX_ERRORCHECK type detects deadlock. */
        (k_mutex->owner == xTaskGetCurrentTaskHandle())) /* Check if locking a currently owned mutex. */
    {
        iStatus = EDEADLK;
    }

    if (iStatus == 0)
    {
        /* Call the correct FreeRTOS mutex take function based on mutex type. */
        /* 允许多重上锁 */
        if (k_mutex->attr.type == PTHREAD_MUTEX_RECURSIVE)
        {
            xFreeRTOSMutexTakeStatus = xSemaphoreTakeRecursive(&k_mutex->semphr, xDelay);
        }
        else
        {
            xFreeRTOSMutexTakeStatus = xSemaphoreTake(&k_mutex->semphr, xDelay);
        }

        /* If the mutex was successfully taken, set its owner. */
        /* 如果持有锁, 改变锁的持有者 */
        if (xFreeRTOSMutexTakeStatus == pdPASS)
        {
            k_mutex->owner = xTaskGetCurrentTaskHandle();
        }
        /* Otherwise, the mutex take timed out. */
        else
        {
            iStatus = ETIMEDOUT;
        }
    }

    return iStatus;
}


/* 尝试持有锁 */
int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
    int iStatus = 0;
    struct timespec xTimeout = {
        .tv_sec = 0,
        .tv_nsec = 0
    };

    /* Attempt to lock with no timeout. */
    iStatus = pthread_mutex_timedlock(mutex, &xTimeout);

    /* POSIX specifies that this function should return EBUSY instead of
     * ETIMEDOUT for attempting to lock a locked mutex. */
    if (iStatus == ETIMEDOUT)
    {
        iStatus = EBUSY;
    }

    return iStatus;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    pthread_mutex_init_if_static(mutex);

    int iStatus = 0;
    k_pthread_mutex *k_mutex = reinterpret_cast<k_pthread_mutex *>(*mutex);

    /* Check if trying to unlock an unowned mutex. */
    /* 检查要释放的锁是否归当前线程所有 */
    if (((k_mutex->attr.type == PTHREAD_MUTEX_ERRORCHECK) || (k_mutex->attr.type == PTHREAD_MUTEX_RECURSIVE)) && (k_mutex->owner != xTaskGetCurrentTaskHandle()))
    {
        iStatus = EPERM;
    }

    if (iStatus == 0)
    {
        /* Call the correct FreeRTOS mutex unlock function based on mutex type. */
        k_mutex->give();

        /* Update the owner of the mutex. A recursive mutex may still have an
         * owner, so it should be updated with xSemaphoreGetMutexHolder. */
        k_mutex->update_owner();
    }

    return iStatus;
}
