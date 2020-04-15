#include "manager.h"
#include <time.h>

LONG __stdcall _handler(PEXCEPTION_POINTERS info);

typedef void (__stdcall *hk_sleep_t)(DWORD duration);
typedef BOOL (__stdcall *hk_beep_t)(DWORD freq, DWORD duration);
typedef DWORD(__stdcall *hk_procid_t)(void);

static hook_manager manager = {};

void __stdcall hk_sleep(DWORD dur) {
	std::cout << "Called hooked sleep! -> " << dur << " ms\n";

	if (manager["sleep"].get() != nullptr)
		manager["sleep"].get()->original<hk_sleep_t>()(dur);

	manager["sleep"]->hook(Sleep, hk_sleep);
}

BOOL __stdcall hk_beep(DWORD freq, DWORD duration) {
	std::cout << "Called hooked beep! -> " << freq << " hz for " << duration << " ms\n";
	BOOL ret = 0;
	
	if (manager["beep"].get() != nullptr)
		ret = manager["beep"].get()->original<hk_beep_t>()(freq, duration);
	
	manager["beep"]->hook(Beep, hk_beep);
	return ret;
}

DWORD __stdcall hk_getprocid() {
	std::cout << "Called hooked procID -> " << rand() % 666 << std::endl;
	manager["proc_id"]->hook(GetCurrentProcessId, hk_getprocid);
	return 20;
}

auto main() -> int {

	manager.init(_handler);

	srand(time(0));

	manager["sleep"]->hook(Sleep, hk_sleep);
	manager["proc_id"]->hook(GetCurrentProcessId, hk_getprocid);
	manager["beep"]->hook(Beep, hk_beep);

	Sleep(10);
	Beep(0, 0); 
	GetCurrentProcessId();

	manager.deinit();

	return 0;
}

#ifdef _WIN64
#define Ip Rip
#else
#define Ip Eip
#endif
#define SINGLE_STEP 0x100

__forceinline VehHook* get_hook(PEXCEPTION_POINTERS info) {

	if (!manager.initialized() || info == nullptr) return nullptr;

	for (auto& [name, data] : manager.all()) {

		if (!data->hooked()) continue;

		if (info->ContextRecord->Ip == (uintptr_t)data->original<void*>())
			return data.get();
	}
	return nullptr;
}

LONG __stdcall _handler(PEXCEPTION_POINTERS info) {
	
	if (info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {

		auto cur = get_hook(info);
		if (cur == nullptr) {
			info->ContextRecord->EFlags |= SINGLE_STEP;
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		auto o_addr		= cur->original<void*>();	
		auto hook_addr	= cur->hook_address<void*>();

		if (info->ContextRecord->Ip == (uintptr_t)o_addr);
			info->ContextRecord->Ip = (uintptr_t)hook_addr;

		info->ContextRecord->EFlags &= ~(SINGLE_STEP);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	else if (info->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		
		for (auto & [name, data] : manager.all()) {

			if (!data->hooked()) continue;

			if (info->ContextRecord->Ip == (uintptr_t)data->original<void*>()) {
				DWORD old;
				VirtualProtect(data->original<void*>(), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
				info->ContextRecord->EFlags &= ~(SINGLE_STEP);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		
		info->ContextRecord->EFlags |= SINGLE_STEP;
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}