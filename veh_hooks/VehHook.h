#pragma once
#include <Windows.h>
#include <memory>
#include <tuple>

class VehHook {
public:
	VehHook() = default;
	~VehHook();
	bool hook(void* original, void* hook);
	bool hooked();
	bool unhook();
	template <typename hook_t>
	hook_t original();
	template <typename hook_t>
	hook_t hook_address();
	DWORD protection();
private:
	std::tuple<bool, MEMORY_BASIC_INFORMATION> _same_page(void* first, void* second);
private:
	bool					 _hooked = false;
	DWORD					 _old = 0;
	void*					 _original = nullptr;
	void*					 _hook = nullptr;
};

inline VehHook::~VehHook() {
	if (_hooked) this->unhook();
}

inline bool VehHook::hook(void* target, void* hook) {

	//if (_hooked) return true;

	_original	= target;
	_hook		= hook;

	auto [same, info_first] = _same_page(target, hook);
	if (same) return false;

	if (VirtualProtect(target, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &_old)) {
		_hooked = true;
		return true;
	}

	return false;
}

inline bool VehHook::hooked() {
	return this != nullptr ? _hooked : false;
}

inline bool VehHook::unhook() {

	if (!_hooked) return false;
	
	if (VirtualProtect(_original, 1, _old, &_old)) {
		_hooked = false;
		return true;
	}
	
	return false;
}

template<typename hook_t>
inline hook_t VehHook::original() {
	return (hook_t)_original;
}

template<typename hook_t>
inline hook_t VehHook::hook_address() {
	return (hook_t)_hook;
}

inline DWORD VehHook::protection() {
	return _old;
}

inline std::tuple<bool, MEMORY_BASIC_INFORMATION> VehHook::_same_page(void* first, void* second) {

	MEMORY_BASIC_INFORMATION mbi_first, mbi_second;

	if (!VirtualQuery(first, &mbi_first, sizeof(mbi_first)))
		return { false, {} };

	if (!VirtualQuery(second, &mbi_second, sizeof(mbi_second)))
		return { false, {} };

	if (mbi_first.BaseAddress == mbi_second.BaseAddress)
		return { true, mbi_first };

	return { false, {} };
}