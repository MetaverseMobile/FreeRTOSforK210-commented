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
#include <atomic.h>
#include <atomic>
#include <climits>
#include <cstring>
#include <errno.h>
#include <kernel/driver_impl.hpp>
#include <platform.h>
#include <pthread.h>
#include <semphr.h>
#include <task.h>
#include <unordered_map>

// Workaround for keeping pthread functions
void *g_pthread_keep[] = {
    (void *)pthread_cond_init,
    (void *)pthread_mutex_init,
    (void *)pthread_self
};


/* 静态全局 ———— 默认线程属性 */
static const pthread_attr_t s_default_thread_attributes = {
    /* 栈空间 ———— 默认 4096 */
    .stacksize = 4096,
    /* 任务优先级  */
    .schedparam = { .sched_priority = tskIDLE_PRIORITY },
    /* 分离的状态 ———— 默认为可合并的 */
    .detachstate = PTHREAD_CREATE_JOINABLE
};



struct k_pthread_key
{
    /* destructor -- 函数指针 */
    void (*destructor)(void *);
};


/* Thread local storage */
struct k_pthread_tls
{
    /* 同多 线程 ID 查找 形式全局变量 */
    std::unordered_map<pthread_key_t, uintptr_t> storage;
};



/* 内核 pthread */
struct k_pthread
{
    /* 属性 */
    pthread_attr_t attr;

    /* 合并 mutex */
    StaticSemaphore_t join_mutex;
    /* 合并 内存屏障 */
    StaticSemaphore_t join_barrier;

    /* 任务函数 */
    void *(*startroutine)(void *);
    /* 参数 */
    void *arg;

    /* 用来在线程运行完成后处理 */
    TaskHandle_t handle;
    /* 返回值 */
    void *ret;


    /* 构造函数 */
    k_pthread(pthread_attr_t attr, void *(*startroutine)(void *), void *arg) noexcept
        : attr(attr), startroutine(startroutine), arg(arg)
    {
        /* 可以合并 */
        if (attr.detachstate == PTHREAD_CREATE_JOINABLE)
        {
            xSemaphoreCreateMutexStatic(&join_mutex);
            xSemaphoreCreateBinaryStatic(&join_barrier);
        }
    }

    /* 创建线程 */
    BaseType_t create() noexcept
    {
        auto ret = xTaskCreate(thread_thunk, "posix", (uint16_t)(attr.stacksize / sizeof(StackType_t)), this, attr.schedparam.sched_priority, &handle);
        if (ret == pdPASS)
        {
            /* Store the pointer to the thread object in the task tag. */
            vTaskSetApplicationTaskTag(handle, (TaskHookFunction_t)this);
        }

        return ret;
    }

    /* 取消线程 */
    void cancel() noexcept
    {
        vTaskSuspendAll();
        on_exit();
        xTaskResumeAll();
    }

private:
    /* 设置参数 */
    static void thread_thunk(void *arg)
    {
        k_pthread *k_thread = reinterpret_cast<k_pthread *>(arg);
        k_thread->ret = k_thread->startroutine(k_thread->arg);

        k_thread->on_exit();
    }

    /* 准备退出 */
    void on_exit()
    {
        /* If this thread is joinable, wait for a call to pthread_join. */
        /* 如果可以合并, 则阻塞等待合并 */
        if (attr.detachstate == PTHREAD_CREATE_JOINABLE)
        {
            xSemaphoreGive(&join_barrier);
            /* Suspend until the call to pthread_join. The caller of pthread_join
             * will perform cleanup. */

            vTaskSuspend(NULL);
        }
        else
        {
            /* For a detached thread, perform cleanup of thread object. */
            /* 若已经分离, 则直接清理线程资源 */
            delete this;
            delete reinterpret_cast<k_pthread_tls *>(pvTaskGetThreadLocalStoragePointer(NULL, PTHREAD_TLS_INDEX));
            vTaskDelete(NULL);
        }
    }
};




/* 创建线程 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*startroutine)(void *), void *arg)
{
    int iStatus = 0;
    k_pthread *k_thrd = NULL;


    /* 为新线程对象申请内存, 如果属性为空则利用默认属性创建线程 */
    k_thrd = new (std::nothrow) k_pthread(attr ? *attr : s_default_thread_attributes, startroutine, arg);


    /* 内存分配失败 */
    if (!k_thrd)
    {
        /* No memory. */
        iStatus = EAGAIN;
    }

    /* 分配成功 */
    if (iStatus == 0)
    {
        /* Suspend all tasks to create a critical section. This ensures that
         * the new thread doesn't exit before a tag is assigned. */
        /* 先暂停所有线程, 保证新线程不会再 tag 赋值之前退出 */
        vTaskSuspendAll();

        /* Create the FreeRTOS task that will run the pthread. */
        /* 创建 RTOS 线程 */
        if (k_thrd->create() != pdPASS)
        {
            /* 创建失败则清理创建的数据 */
            delete k_thrd;
            iStatus = EAGAIN;
        }
        else
        {
            /* 如果创建成功, 则将线程数据交给用户 */
            *thread = reinterpret_cast<uintptr_t>(k_thrd);
        }

        /* 继续运行所有线程 */
        xTaskResumeAll();
    }

    return iStatus;
}



/* 合并线程 */
int pthread_join(pthread_t pthread, void **retval)
{
    int iStatus = 0;

    /* 将线程结构转换为内核数据 */
    k_pthread *k_thrd = reinterpret_cast<k_pthread *>(pthread);

    /* 该线程的属性必须是 joinable */
    if (k_thrd->attr.detachstate != PTHREAD_CREATE_JOINABLE)
    {
        iStatus = EDEADLK;
    }

    /* Only one thread may attempt to join another. Lock the join mutex
     * to prevent other threads from calling pthread_join on the same thread. */
    /* 只能有一个线程和其他线程合并, 因此为 join 上锁来组织其他线程对同一个线程进行合并 */
    if (iStatus == 0)
    {
        if (xSemaphoreTake(&k_thrd->join_mutex, 0) != pdPASS)
        {
            /* Another thread has already joined the requested thread, which would
             * cause this thread to wait forever. */
            iStatus = EDEADLK;
        }
    }

    /* Attempting to join the calling thread would cause a deadlock. */
    if (iStatus == 0)
    {
        /* 试图合并调用线程回导致死锁 */
        if (pthread_equal(pthread_self(), pthread) != 0)
        {
            iStatus = EDEADLK;
        }
    }


    if (iStatus == 0)
    {
        /* Wait for the joining thread to finish. Because this call waits forever,
         * it should never fail. */
        /* 等待线程结束 */
        (void)xSemaphoreTake(&k_thrd->join_barrier, portMAX_DELAY);

        /* Create a critical section to clean up the joined thread. */
        /* 为了清理被合并的线程的数据, 先暂停所有任务 */
        vTaskSuspendAll();

        /* Release xJoinBarrier and delete it. */
        /* 释放 xJoinBarrier 并将其删除 */
        (void)xSemaphoreGive(&k_thrd->join_barrier);
        vSemaphoreDelete(&k_thrd->join_barrier);

        /* Release xJoinMutex and delete it. */
        /* 释放 xJoinMutex 并将其删除 */
        (void)xSemaphoreGive(&k_thrd->join_mutex);
        vSemaphoreDelete(&k_thrd->join_mutex);

        /* Set the return value. */
        /* 如果存在返回值, 则设置返回值 */
        if (retval != NULL)
        {
            *retval = k_thrd->ret;
        }

        /* Free the thread object. */
        /* 释放 线程本地储存 的数据 */
        delete reinterpret_cast<k_pthread_tls *>(pvTaskGetThreadLocalStoragePointer(k_thrd->handle, PTHREAD_TLS_INDEX));

        /* Delete the FreeRTOS task that ran the thread. */
        /* 对线程做最后处理 */
        vTaskDelete(k_thrd->handle);
        /* 删除任务本身的数据结构 */
        delete k_thrd;

        /* End the critical section. */
        xTaskResumeAll();
    }

    return iStatus;
}




/* 返回当前线程对象的应用 */
pthread_t pthread_self(void)
{
    /* Return a reference to this pthread object, which is stored in the FreeRTOS task tag. */
    return (uintptr_t)xTaskGetApplicationTaskTag(NULL);
}



/* 取消线程 */
int pthread_cancel(pthread_t pthread)
{
    k_pthread *k_thrd = reinterpret_cast<k_pthread *>(pthread);

    k_thrd->cancel();

    return 0;
}



/* 第一个参数为指向一个键值的指针，第二个参数指明了一个destructor函数，
如果这个参数不为空，那么当每个线程结束时，系统将调用这个函数来释放绑定在这个键上的内存块 */
int pthread_key_create(pthread_key_t *__key, void (*__destructor)(void *))
{
    auto k_key = new (std::nothrow) k_pthread_key;
    if (k_key)
    {
        k_key->destructor = __destructor;

        *__key = reinterpret_cast<uintptr_t>(k_key);
        return 0;
    }

    return ENOMEM;
}

int pthread_key_delete(pthread_key_t key)
{
    auto k_key = reinterpret_cast<k_pthread_key *>(key);
    delete k_key;
    return 0;
}


/* 按照键从 TLS 查找变量 */
void *pthread_getspecific(pthread_key_t key)
{
    auto tls = reinterpret_cast<k_pthread_tls *>(pvTaskGetThreadLocalStoragePointer(NULL, PTHREAD_TLS_INDEX));

    if (tls)
    {
        auto it = tls->storage.find(key);
        if (it != tls->storage.end())
            return reinterpret_cast<void *>(it->second);
    }

    return nullptr;
}



/* 设置 TLS 的某个键的 */
int pthread_setspecific(pthread_key_t key, const void *value)
{
    auto tls = reinterpret_cast<k_pthread_tls *>(pvTaskGetThreadLocalStoragePointer(NULL, PTHREAD_TLS_INDEX));
    if (!tls)
    {
        tls = new (std::nothrow) k_pthread_tls;
        if (!tls)
            return ENOMEM;
        vTaskSetThreadLocalStoragePointer(NULL, PTHREAD_TLS_INDEX, tls);
    }

    try
    {
        tls->storage[key] = uintptr_t(value);
        return 0;
    }
    catch (...)
    {
        return ENOMEM;
    }
}


/* 在所有线程中都只执行 1 次 */
int pthread_once(pthread_once_t *once_control, void (*init_routine)(void))
{
    while (true)
    {
        /* 原子读 ———— 发现已经运行过则直接返回 */
        if (atomic_read(&once_control->init_executed) == 1)
            return 0;


        if (atomic_cas(&once_control->init_executed, 0, 2) == 0)
            break;
    }

    /* 执行 */
    init_routine();

    /* 原子写 ———— 标记该任务已经完成 */
    atomic_set(&once_control->init_executed, 1);
    return 0;
}



/* 比较线程 ID 是否相同 */
int pthread_equal(pthread_t t1, pthread_t t2)
{
    int iStatus = 0;

    /* 比较线程 ID */
    if (t1 && t2)
    {
        iStatus = (t1 == t2);
    }

    return iStatus;
}
