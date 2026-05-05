//memory utils
//author: zerrocxste

#ifndef MEMORY_UTILS
#define MEMORY_UTILS

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <vector>

namespace memory_utils
{
#ifdef _WIN64
#define PTRMAXVAL ((PVOID)0x000F000000000000)
#elif _WIN32
#define PTRMAXVAL ((PVOID)0xFFF00000)
#endif

	__forceinline bool is_valid_ptr(PVOID ptr, size_t len = sizeof(void*)) {
		return (ptr >= (PVOID)0x10000) && (ptr < PTRMAXVAL) && ptr != nullptr && !IsBadReadPtr(ptr, len);
	}

	extern DWORD get_module_size(DWORD_PTR address);

	extern DWORD_PTR pattern_scanner_module(HMODULE module, const char* pattern, const char* mask, DWORD scan_speed = 0x1);

	DWORD_PTR pattern_scanner(
		DWORD_PTR start, DWORD_PTR end,
		const char* pattern, const char* mask,
		DWORD scan_speed,
		DWORD page_prot = PAGE_EXECUTE_READ, DWORD page_state = MEM_COMMIT, DWORD page_type = MEM_PRIVATE);

	std::vector<DWORD_PTR> pattern_scanner_vec(
		DWORD_PTR start, DWORD_PTR end,
		const char* pattern, const char* mask,
		DWORD scan_speed,
		DWORD page_prot = PAGE_EXECUTE_READ, DWORD page_state = MEM_COMMIT, DWORD page_type = MEM_PRIVATE);

	__forceinline uintptr_t ptr_path(uintptr_t ptr) {
		return ptr;
	}

	__forceinline uintptr_t ptr_path(uintptr_t ptr, uintptr_t last_offset) {
		return ptr + last_offset;
	}

	template <class... _Args>
	__forceinline uintptr_t ptr_path(uintptr_t ptr, uintptr_t offset, _Args... args) {
		ptr += offset;
		return is_valid_ptr((void*)ptr) ? ptr_path(*(uintptr_t*)ptr, args...) : 0;
	}

	template <class _Ty, class _First, class... _Args>
	__forceinline _Ty read(_First ptr, _Args... args) {
		uintptr_t ret = ptr_path((uintptr_t)ptr, uintptr_t(args)...);
		return is_valid_ptr((void*)ret, sizeof(_Ty))
			? *(_Ty*)ret
			: _Ty{};
	}
}

#endif // MEMORY_UTILS
