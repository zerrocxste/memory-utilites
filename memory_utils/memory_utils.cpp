#include "memory_utils.h"

namespace memory_utils
{
	static HMODULE base;

	DWORD get_module_size(DWORD_PTR address)
	{
		return PIMAGE_NT_HEADERS(address + PIMAGE_DOS_HEADER(address)->e_lfanew)->OptionalHeader.SizeOfImage;
	}

	DWORD_PTR compare_mem(const char* pattern, const char* mask, DWORD_PTR base, DWORD size, const int patternLength, DWORD speed)
	{
		for (DWORD i = 0; i < size - patternLength; i += speed)
		{
			bool found = true;
			for (int j = 0; j < patternLength; j++)
			{
				if (mask[j] == '?')
					continue;

				if (pattern[j] != *(char*)(base + i + j))
				{
					found = false;
					break;
				}
			}

			if (found)
			{
				return base + i;
			}
		}

		return NULL;
	}

	DWORD_PTR pattern_scanner_module(HMODULE module, const char* pattern, const char* mask, DWORD scan_speed)
	{
		auto base = (DWORD_PTR)module;
		auto size = get_module_size(base);

		int patternLength = (int)strlen(mask);

		return compare_mem(pattern, mask, base, size, patternLength, scan_speed);
	}

	DWORD_PTR pattern_scanner(
		DWORD_PTR start, DWORD_PTR end,
		const char* pattern, const char* mask,
		DWORD scan_speed,
		DWORD page_prot, DWORD page_state, DWORD page_type)
	{
		auto pattern_length = strlen(mask);

		MEMORY_BASIC_INFORMATION mbi{};
		while (start < end &&
			VirtualQuery((void*)start, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
		{
			auto fix_seg = false;
			DWORD_PTR start_seg = (DWORD_PTR)mbi.BaseAddress;
			DWORD_PTR size_seg = mbi.RegionSize;

			if (page_prot != 0 && mbi.Protect != page_prot)
				goto next_seg;

			if (page_state != 0 && mbi.State != page_state)
				goto next_seg;

			if (page_type != 0 && mbi.Type != page_type)
				goto next_seg;

			if (start > start_seg)
			{
				size_seg -= start - start_seg;
				fix_seg = true;
			}

			if (auto compare_result = compare_mem(pattern, mask, start, end, pattern_length, scan_speed))
				return compare_result;

		next_seg:

			fix_seg ? start += size_seg : start = start_seg + size_seg;
		}

		return NULL;
	}

	std::vector<DWORD_PTR> pattern_scanner_vec(
		DWORD_PTR start, DWORD_PTR end,
		const char* pattern, const char* mask,
		DWORD scan_speed,
		DWORD page_prot, DWORD page_state, DWORD page_type)
	{
		std::vector<DWORD_PTR>ret;

		auto pattern_length = strlen(mask);

		MEMORY_BASIC_INFORMATION mbi{};
		while (start < end &&
			VirtualQuery((void*)start, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
		{
			auto fix_seg = false;
			DWORD_PTR start_seg = (DWORD_PTR)mbi.BaseAddress;
			DWORD_PTR size_seg = mbi.RegionSize;

			if (page_prot != 0 && mbi.Protect != page_prot)
				goto next_seg;

			if (page_state != 0 && mbi.State != page_state)
				goto next_seg;

			if (page_type != 0 && mbi.Type != page_type)
				goto next_seg;

			if (start > start_seg)
			{
				size_seg -= start - start_seg;
				fix_seg = true;
			}

			if (auto compare_result = compare_mem(pattern, mask, start, end, pattern_length, scan_speed))
				ret.push_back(compare_result);

		next_seg:

			fix_seg ? start += size_seg : start = start_seg + size_seg;
		}

		return ret;
	}
}
