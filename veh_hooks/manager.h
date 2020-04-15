#pragma once

#include <iostream>
#include <map>
#include <string>
#include "VehHook.h"

typedef std::map<std::string, std::shared_ptr<VehHook>> hooks;

class hook_manager {
public:
	hook_manager() = default;
	~hook_manager();
	bool init(PVECTORED_EXCEPTION_HANDLER handler);
	bool deinit();
	std::shared_ptr<VehHook> operator[](const std::string name);
	hooks& all();
	DWORD& protection();
	bool initialized();
private:
	hooks _hooks = {};
	bool _initialized = false;
	void* _veh_handle = nullptr;
	PVECTORED_EXCEPTION_HANDLER	_handler = nullptr;
};