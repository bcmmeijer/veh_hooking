#include "manager.h"

hook_manager hook_manager::_manager;

hook_manager::~hook_manager() {
	if (_initialized) this->deinit();
}

bool hook_manager::init(PVECTORED_EXCEPTION_HANDLER handler) {
	_veh_handle = AddVectoredExceptionHandler(true, handler);
	if (_veh_handle != nullptr) {
		_initialized = true;
		return true;
	}
	return false;
}

bool hook_manager::deinit() {

	if (!_initialized)
		return false;
	
	if (_veh_handle == nullptr)
		return false;
	
	for (auto& [name, hook] : _hooks)
		hook->unhook();

	if (RemoveVectoredExceptionHandler(_veh_handle)) {
		_initialized = false;
		_veh_handle = nullptr;
		return true;
	}

	return false;
}

std::shared_ptr<VehHook> hook_manager::operator[](const std::string name) {
	
	if (_hooks.find(name) != _hooks.end())
		return _hooks[name];
	
	_hooks[name] = std::make_shared<VehHook>();
	return _hooks[name];
}

hooks& hook_manager::all() {
	return _hooks;
}

bool hook_manager::initialized() {
	return _initialized;
}

hook_manager& hook_manager::get() {
	return _manager;
}