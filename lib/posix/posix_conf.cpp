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
#include <sys/unistd.h>


/* 获得系统参数 */
long sysconf(int __name)
{
    switch (__name)
    {
        /* 只支持页字节数的查询 */
        case _SC_NPROCESSORS_CONF:
            return 1;
        default:
            break;
    }

    return -1;
}
