/* Observe the stack reserve inherited from the executable, without overflowing it. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

static SIZE_T current_stack_reserve(void)
{
    volatile unsigned char local = 0;
    MEMORY_BASIC_INFORMATION info;
    const NT_TIB *tib = (const NT_TIB *)NtCurrentTeb();
    if (VirtualQuery((const void *)&local, &info, sizeof(info)) != sizeof(info))
        return 0;
    return (SIZE_T)((uintptr_t)tib->StackBase - (uintptr_t)info.AllocationBase);
}

static DWORD WINAPI observe_worker(LPVOID output)
{
    *(SIZE_T *)output = current_stack_reserve();
    return 0;
}

static int observe_thread(SIZE_T size, DWORD flags, SIZE_T *output)
{
    HANDLE thread = CreateThread(NULL, size, observe_worker, output, flags, NULL);
    if (!thread) return 0;
    DWORD wait = WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    return wait == WAIT_OBJECT_0;
}

int main(void)
{
    SIZE_T main_reserve = current_stack_reserve();
    SIZE_T default_reserve = 0, explicit_reserve = 0;
    /* Explicit reservation is an independent measurement control. */
    if (!observe_thread(0, 0, &default_reserve) ||
        !observe_thread(1048576, STACK_SIZE_PARAM_IS_A_RESERVATION, &explicit_reserve))
    {
        fprintf(stderr, "Could not observe worker stack reserve\n");
        return 2;
    }
    printf("{\"main_reserve\":%llu,\"default_worker_reserve\":%llu,"
           "\"explicit_worker_reserve\":%llu}\n",
           (unsigned long long)main_reserve,
           (unsigned long long)default_reserve,
           (unsigned long long)explicit_reserve);
    /* A deliberate tiny /STACK or --stack setting affects new default workers too. */
    return !(main_reserve >= 1048576 && default_reserve >= 1048576 &&
             explicit_reserve == 1048576);
}
