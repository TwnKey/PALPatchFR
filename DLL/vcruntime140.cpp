#include <windows.h>
#include <stdio.h>
#include "hook_macro.h"
#include <vector>
HINSTANCE mHinst = 0, mHinstDLL = 0;

UINT_PTR mProcs[81] = {0};


bool RewriteMemoryEx(ULONG_PTR addr, std::vector<BYTE> BytesToWrite) {
	DWORD dwProtect, dwProtect2;
	if (VirtualProtect((LPVOID)addr, BytesToWrite.size(), PAGE_EXECUTE_READWRITE, &dwProtect)) {
		unsigned char* addr_bytes_to_write = BytesToWrite.data();
		memcpy((void*)addr, addr_bytes_to_write, BytesToWrite.size());
		VirtualProtect((LPVOID)addr, BytesToWrite.size(), dwProtect, &dwProtect2);

		return true;
	}
	else {
		return false;
	}
}

std::vector<BYTE> number_to_bytes(int c, int nb_bytes) {
	std::vector<BYTE> res;
	for (int i = 0; i < nb_bytes; i++) {
		res.push_back((c & (0xff << (8 * i))) >> (8 * i));
	}
	return res;

}

LPCSTR mImportNames[] = {
  "_CreateFrameInfo",
  "_CxxThrowException",
  "_EH_prolog",
  "_FindAndUnlinkFrame",
  "_IsExceptionObjectToBeDestroyed",
  "_NLG_Dispatch2",
  "_NLG_Return",
  "_NLG_Return2",
  "_SetWinRTOutOfMemoryExceptionCallback",
  "__AdjustPointer",
  "__BuildCatchObject",
  "__BuildCatchObjectHelper",
  "__CxxDetectRethrow",
  "__CxxExceptionFilter",
  "__CxxFrameHandler",
  "__CxxFrameHandler2",
  "__CxxFrameHandler3",
  "__CxxLongjmpUnwind",
  "__CxxQueryExceptionSize",
  "__CxxRegisterExceptionObject",
  "__CxxUnregisterExceptionObject",
  "__DestructExceptionObject",
  "__FrameUnwindFilter",
  "__GetPlatformExceptionInfo",
  "__RTCastToVoid",
  "__RTDynamicCast",
  "__RTtypeid",
  "__TypeMatch",
  "__current_exception",
  "__current_exception_context",
  "__intrinsic_setjmp",
  "__processing_throw",
  "__report_gsfailure",
  "__std_exception_copy",
  "__std_exception_destroy",
  "__std_terminate",
  "__std_type_info_compare",
  "__std_type_info_destroy_list",
  "__std_type_info_hash",
  "__std_type_info_name",
  "__telemetry_main_invoke_trigger",
  "__telemetry_main_return_trigger",
  "__unDName",
  "__unDNameEx",
  "__uncaught_exception",
  "__uncaught_exceptions",
  "__vcrt_GetModuleFileNameW",
  "__vcrt_GetModuleHandleW",
  "__vcrt_InitializeCriticalSectionEx",
  "__vcrt_LoadLibraryExW",
  "_chkesp",
  "_except_handler2",
  "_except_handler3",
  "_except_handler4_common",
  "_get_purecall_handler",
  "_get_unexpected",
  "_global_unwind2",
  "_is_exception_typeof",
  "_local_unwind2",
  "_local_unwind4",
  "_longjmpex",
  "_purecall",
  "_seh_longjmp_unwind",
  "_seh_longjmp_unwind4",
  "_set_purecall_handler",
  "_set_se_translator",
  "_setjmp3",
  "longjmp",
  "memchr",
  "memcmp",
  "memcpy",
  "memmove",
  "memset",
  "set_unexpected",
  "strchr",
  "strrchr",
  "strstr",
  "unexpected",
  "wcschr",
  "wcsrchr",
  "wcsstr",
};

#ifndef _DEBUG
inline void log_info(const char* info) {
}
#else
FILE* debug;
inline void log_info(const char* info) {
  fprintf(debug, "%s\n", info);
  fflush(debug);
}
#endif

#include "empty.h"

inline void _hook_setup() {
#ifdef _CREATEFRAMEINFO
  _CreateFrameInfo_real = (_CreateFrameInfo_ptr)mProcs[0];
  mProcs[0] = (UINT_PTR)&_CreateFrameInfo_fake;
#endif
#ifdef _CXXTHROWEXCEPTION
  _CxxThrowException_real = (_CxxThrowException_ptr)mProcs[1];
  mProcs[1] = (UINT_PTR)&_CxxThrowException_fake;
#endif
#ifdef _EH_PROLOG
  _EH_prolog_real = (_EH_prolog_ptr)mProcs[2];
  mProcs[2] = (UINT_PTR)&_EH_prolog_fake;
#endif
#ifdef _FINDANDUNLINKFRAME
  _FindAndUnlinkFrame_real = (_FindAndUnlinkFrame_ptr)mProcs[3];
  mProcs[3] = (UINT_PTR)&_FindAndUnlinkFrame_fake;
#endif
#ifdef _ISEXCEPTIONOBJECTTOBEDESTROYED
  _IsExceptionObjectToBeDestroyed_real = (_IsExceptionObjectToBeDestroyed_ptr)mProcs[4];
  mProcs[4] = (UINT_PTR)&_IsExceptionObjectToBeDestroyed_fake;
#endif
#ifdef _NLG_DISPATCH2
  _NLG_Dispatch2_real = (_NLG_Dispatch2_ptr)mProcs[5];
  mProcs[5] = (UINT_PTR)&_NLG_Dispatch2_fake;
#endif
#ifdef _NLG_RETURN
  _NLG_Return_real = (_NLG_Return_ptr)mProcs[6];
  mProcs[6] = (UINT_PTR)&_NLG_Return_fake;
#endif
#ifdef _NLG_RETURN2
  _NLG_Return2_real = (_NLG_Return2_ptr)mProcs[7];
  mProcs[7] = (UINT_PTR)&_NLG_Return2_fake;
#endif
#ifdef _SETWINRTOUTOFMEMORYEXCEPTIONCALLBACK
  _SetWinRTOutOfMemoryExceptionCallback_real = (_SetWinRTOutOfMemoryExceptionCallback_ptr)mProcs[8];
  mProcs[8] = (UINT_PTR)&_SetWinRTOutOfMemoryExceptionCallback_fake;
#endif
#ifdef __ADJUSTPOINTER
  __AdjustPointer_real = (__AdjustPointer_ptr)mProcs[9];
  mProcs[9] = (UINT_PTR)&__AdjustPointer_fake;
#endif
#ifdef __BUILDCATCHOBJECT
  __BuildCatchObject_real = (__BuildCatchObject_ptr)mProcs[10];
  mProcs[10] = (UINT_PTR)&__BuildCatchObject_fake;
#endif
#ifdef __BUILDCATCHOBJECTHELPER
  __BuildCatchObjectHelper_real = (__BuildCatchObjectHelper_ptr)mProcs[11];
  mProcs[11] = (UINT_PTR)&__BuildCatchObjectHelper_fake;
#endif
#ifdef __CXXDETECTRETHROW
  __CxxDetectRethrow_real = (__CxxDetectRethrow_ptr)mProcs[12];
  mProcs[12] = (UINT_PTR)&__CxxDetectRethrow_fake;
#endif
#ifdef __CXXEXCEPTIONFILTER
  __CxxExceptionFilter_real = (__CxxExceptionFilter_ptr)mProcs[13];
  mProcs[13] = (UINT_PTR)&__CxxExceptionFilter_fake;
#endif
#ifdef __CXXFRAMEHANDLER
  __CxxFrameHandler_real = (__CxxFrameHandler_ptr)mProcs[14];
  mProcs[14] = (UINT_PTR)&__CxxFrameHandler_fake;
#endif
#ifdef __CXXFRAMEHANDLER2
  __CxxFrameHandler2_real = (__CxxFrameHandler2_ptr)mProcs[15];
  mProcs[15] = (UINT_PTR)&__CxxFrameHandler2_fake;
#endif
#ifdef __CXXFRAMEHANDLER3
  __CxxFrameHandler3_real = (__CxxFrameHandler3_ptr)mProcs[16];
  mProcs[16] = (UINT_PTR)&__CxxFrameHandler3_fake;
#endif
#ifdef __CXXLONGJMPUNWIND
  __CxxLongjmpUnwind_real = (__CxxLongjmpUnwind_ptr)mProcs[17];
  mProcs[17] = (UINT_PTR)&__CxxLongjmpUnwind_fake;
#endif
#ifdef __CXXQUERYEXCEPTIONSIZE
  __CxxQueryExceptionSize_real = (__CxxQueryExceptionSize_ptr)mProcs[18];
  mProcs[18] = (UINT_PTR)&__CxxQueryExceptionSize_fake;
#endif
#ifdef __CXXREGISTEREXCEPTIONOBJECT
  __CxxRegisterExceptionObject_real = (__CxxRegisterExceptionObject_ptr)mProcs[19];
  mProcs[19] = (UINT_PTR)&__CxxRegisterExceptionObject_fake;
#endif
#ifdef __CXXUNREGISTEREXCEPTIONOBJECT
  __CxxUnregisterExceptionObject_real = (__CxxUnregisterExceptionObject_ptr)mProcs[20];
  mProcs[20] = (UINT_PTR)&__CxxUnregisterExceptionObject_fake;
#endif
#ifdef __DESTRUCTEXCEPTIONOBJECT
  __DestructExceptionObject_real = (__DestructExceptionObject_ptr)mProcs[21];
  mProcs[21] = (UINT_PTR)&__DestructExceptionObject_fake;
#endif
#ifdef __FRAMEUNWINDFILTER
  __FrameUnwindFilter_real = (__FrameUnwindFilter_ptr)mProcs[22];
  mProcs[22] = (UINT_PTR)&__FrameUnwindFilter_fake;
#endif
#ifdef __GETPLATFORMEXCEPTIONINFO
  __GetPlatformExceptionInfo_real = (__GetPlatformExceptionInfo_ptr)mProcs[23];
  mProcs[23] = (UINT_PTR)&__GetPlatformExceptionInfo_fake;
#endif
#ifdef __RTCASTTOVOID
  __RTCastToVoid_real = (__RTCastToVoid_ptr)mProcs[24];
  mProcs[24] = (UINT_PTR)&__RTCastToVoid_fake;
#endif
#ifdef __RTDYNAMICCAST
  __RTDynamicCast_real = (__RTDynamicCast_ptr)mProcs[25];
  mProcs[25] = (UINT_PTR)&__RTDynamicCast_fake;
#endif
#ifdef __RTTYPEID
  __RTtypeid_real = (__RTtypeid_ptr)mProcs[26];
  mProcs[26] = (UINT_PTR)&__RTtypeid_fake;
#endif
#ifdef __TYPEMATCH
  __TypeMatch_real = (__TypeMatch_ptr)mProcs[27];
  mProcs[27] = (UINT_PTR)&__TypeMatch_fake;
#endif
#ifdef __CURRENT_EXCEPTION
  __current_exception_real = (__current_exception_ptr)mProcs[28];
  mProcs[28] = (UINT_PTR)&__current_exception_fake;
#endif
#ifdef __CURRENT_EXCEPTION_CONTEXT
  __current_exception_context_real = (__current_exception_context_ptr)mProcs[29];
  mProcs[29] = (UINT_PTR)&__current_exception_context_fake;
#endif
#ifdef __INTRINSIC_SETJMP
  __intrinsic_setjmp_real = (__intrinsic_setjmp_ptr)mProcs[30];
  mProcs[30] = (UINT_PTR)&__intrinsic_setjmp_fake;
#endif
#ifdef __PROCESSING_THROW
  __processing_throw_real = (__processing_throw_ptr)mProcs[31];
  mProcs[31] = (UINT_PTR)&__processing_throw_fake;
#endif
#ifdef __REPORT_GSFAILURE
  __report_gsfailure_real = (__report_gsfailure_ptr)mProcs[32];
  mProcs[32] = (UINT_PTR)&__report_gsfailure_fake;
#endif
#ifdef __STD_EXCEPTION_COPY
  __std_exception_copy_real = (__std_exception_copy_ptr)mProcs[33];
  mProcs[33] = (UINT_PTR)&__std_exception_copy_fake;
#endif
#ifdef __STD_EXCEPTION_DESTROY
  __std_exception_destroy_real = (__std_exception_destroy_ptr)mProcs[34];
  mProcs[34] = (UINT_PTR)&__std_exception_destroy_fake;
#endif
#ifdef __STD_TERMINATE
  __std_terminate_real = (__std_terminate_ptr)mProcs[35];
  mProcs[35] = (UINT_PTR)&__std_terminate_fake;
#endif
#ifdef __STD_TYPE_INFO_COMPARE
  __std_type_info_compare_real = (__std_type_info_compare_ptr)mProcs[36];
  mProcs[36] = (UINT_PTR)&__std_type_info_compare_fake;
#endif
#ifdef __STD_TYPE_INFO_DESTROY_LIST
  __std_type_info_destroy_list_real = (__std_type_info_destroy_list_ptr)mProcs[37];
  mProcs[37] = (UINT_PTR)&__std_type_info_destroy_list_fake;
#endif
#ifdef __STD_TYPE_INFO_HASH
  __std_type_info_hash_real = (__std_type_info_hash_ptr)mProcs[38];
  mProcs[38] = (UINT_PTR)&__std_type_info_hash_fake;
#endif
#ifdef __STD_TYPE_INFO_NAME
  __std_type_info_name_real = (__std_type_info_name_ptr)mProcs[39];
  mProcs[39] = (UINT_PTR)&__std_type_info_name_fake;
#endif
#ifdef __TELEMETRY_MAIN_INVOKE_TRIGGER
  __telemetry_main_invoke_trigger_real = (__telemetry_main_invoke_trigger_ptr)mProcs[40];
  mProcs[40] = (UINT_PTR)&__telemetry_main_invoke_trigger_fake;
#endif
#ifdef __TELEMETRY_MAIN_RETURN_TRIGGER
  __telemetry_main_return_trigger_real = (__telemetry_main_return_trigger_ptr)mProcs[41];
  mProcs[41] = (UINT_PTR)&__telemetry_main_return_trigger_fake;
#endif
#ifdef __UNDNAME
  __unDName_real = (__unDName_ptr)mProcs[42];
  mProcs[42] = (UINT_PTR)&__unDName_fake;
#endif
#ifdef __UNDNAMEEX
  __unDNameEx_real = (__unDNameEx_ptr)mProcs[43];
  mProcs[43] = (UINT_PTR)&__unDNameEx_fake;
#endif
#ifdef __UNCAUGHT_EXCEPTION
  __uncaught_exception_real = (__uncaught_exception_ptr)mProcs[44];
  mProcs[44] = (UINT_PTR)&__uncaught_exception_fake;
#endif
#ifdef __UNCAUGHT_EXCEPTIONS
  __uncaught_exceptions_real = (__uncaught_exceptions_ptr)mProcs[45];
  mProcs[45] = (UINT_PTR)&__uncaught_exceptions_fake;
#endif
#ifdef __VCRT_GETMODULEFILENAMEW
  __vcrt_GetModuleFileNameW_real = (__vcrt_GetModuleFileNameW_ptr)mProcs[46];
  mProcs[46] = (UINT_PTR)&__vcrt_GetModuleFileNameW_fake;
#endif
#ifdef __VCRT_GETMODULEHANDLEW
  __vcrt_GetModuleHandleW_real = (__vcrt_GetModuleHandleW_ptr)mProcs[47];
  mProcs[47] = (UINT_PTR)&__vcrt_GetModuleHandleW_fake;
#endif
#ifdef __VCRT_INITIALIZECRITICALSECTIONEX
  __vcrt_InitializeCriticalSectionEx_real = (__vcrt_InitializeCriticalSectionEx_ptr)mProcs[48];
  mProcs[48] = (UINT_PTR)&__vcrt_InitializeCriticalSectionEx_fake;
#endif
#ifdef __VCRT_LOADLIBRARYEXW
  __vcrt_LoadLibraryExW_real = (__vcrt_LoadLibraryExW_ptr)mProcs[49];
  mProcs[49] = (UINT_PTR)&__vcrt_LoadLibraryExW_fake;
#endif
#ifdef _CHKESP
  _chkesp_real = (_chkesp_ptr)mProcs[50];
  mProcs[50] = (UINT_PTR)&_chkesp_fake;
#endif
#ifdef _EXCEPT_HANDLER2
  _except_handler2_real = (_except_handler2_ptr)mProcs[51];
  mProcs[51] = (UINT_PTR)&_except_handler2_fake;
#endif
#ifdef _EXCEPT_HANDLER3
  _except_handler3_real = (_except_handler3_ptr)mProcs[52];
  mProcs[52] = (UINT_PTR)&_except_handler3_fake;
#endif
#ifdef _EXCEPT_HANDLER4_COMMON
  _except_handler4_common_real = (_except_handler4_common_ptr)mProcs[53];
  mProcs[53] = (UINT_PTR)&_except_handler4_common_fake;
#endif
#ifdef _GET_PURECALL_HANDLER
  _get_purecall_handler_real = (_get_purecall_handler_ptr)mProcs[54];
  mProcs[54] = (UINT_PTR)&_get_purecall_handler_fake;
#endif
#ifdef _GET_UNEXPECTED
  _get_unexpected_real = (_get_unexpected_ptr)mProcs[55];
  mProcs[55] = (UINT_PTR)&_get_unexpected_fake;
#endif
#ifdef _GLOBAL_UNWIND2
  _global_unwind2_real = (_global_unwind2_ptr)mProcs[56];
  mProcs[56] = (UINT_PTR)&_global_unwind2_fake;
#endif
#ifdef _IS_EXCEPTION_TYPEOF
  _is_exception_typeof_real = (_is_exception_typeof_ptr)mProcs[57];
  mProcs[57] = (UINT_PTR)&_is_exception_typeof_fake;
#endif
#ifdef _LOCAL_UNWIND2
  _local_unwind2_real = (_local_unwind2_ptr)mProcs[58];
  mProcs[58] = (UINT_PTR)&_local_unwind2_fake;
#endif
#ifdef _LOCAL_UNWIND4
  _local_unwind4_real = (_local_unwind4_ptr)mProcs[59];
  mProcs[59] = (UINT_PTR)&_local_unwind4_fake;
#endif
#ifdef _LONGJMPEX
  _longjmpex_real = (_longjmpex_ptr)mProcs[60];
  mProcs[60] = (UINT_PTR)&_longjmpex_fake;
#endif
#ifdef _PURECALL
  _purecall_real = (_purecall_ptr)mProcs[61];
  mProcs[61] = (UINT_PTR)&_purecall_fake;
#endif
#ifdef _SEH_LONGJMP_UNWIND
  _seh_longjmp_unwind_real = (_seh_longjmp_unwind_ptr)mProcs[62];
  mProcs[62] = (UINT_PTR)&_seh_longjmp_unwind_fake;
#endif
#ifdef _SEH_LONGJMP_UNWIND4
  _seh_longjmp_unwind4_real = (_seh_longjmp_unwind4_ptr)mProcs[63];
  mProcs[63] = (UINT_PTR)&_seh_longjmp_unwind4_fake;
#endif
#ifdef _SET_PURECALL_HANDLER
  _set_purecall_handler_real = (_set_purecall_handler_ptr)mProcs[64];
  mProcs[64] = (UINT_PTR)&_set_purecall_handler_fake;
#endif
#ifdef _SET_SE_TRANSLATOR
  _set_se_translator_real = (_set_se_translator_ptr)mProcs[65];
  mProcs[65] = (UINT_PTR)&_set_se_translator_fake;
#endif
#ifdef _SETJMP3
  _setjmp3_real = (_setjmp3_ptr)mProcs[66];
  mProcs[66] = (UINT_PTR)&_setjmp3_fake;
#endif
#ifdef LONGJMP
  longjmp_real = (longjmp_ptr)mProcs[67];
  mProcs[67] = (UINT_PTR)&longjmp_fake;
#endif
#ifdef MEMCHR
  memchr_real = (memchr_ptr)mProcs[68];
  mProcs[68] = (UINT_PTR)&memchr_fake;
#endif
#ifdef MEMCMP
  memcmp_real = (memcmp_ptr)mProcs[69];
  mProcs[69] = (UINT_PTR)&memcmp_fake;
#endif
#ifdef MEMCPY
  memcpy_real = (memcpy_ptr)mProcs[70];
  mProcs[70] = (UINT_PTR)&memcpy_fake;
#endif
#ifdef MEMMOVE
  memmove_real = (memmove_ptr)mProcs[71];
  mProcs[71] = (UINT_PTR)&memmove_fake;
#endif
#ifdef MEMSET
  memset_real = (memset_ptr)mProcs[72];
  mProcs[72] = (UINT_PTR)&memset_fake;
#endif
#ifdef SET_UNEXPECTED
  set_unexpected_real = (set_unexpected_ptr)mProcs[73];
  mProcs[73] = (UINT_PTR)&set_unexpected_fake;
#endif
#ifdef STRCHR
  strchr_real = (strchr_ptr)mProcs[74];
  mProcs[74] = (UINT_PTR)&strchr_fake;
#endif
#ifdef STRRCHR
  strrchr_real = (strrchr_ptr)mProcs[75];
  mProcs[75] = (UINT_PTR)&strrchr_fake;
#endif
#ifdef STRSTR
  strstr_real = (strstr_ptr)mProcs[76];
  mProcs[76] = (UINT_PTR)&strstr_fake;
#endif
#ifdef UNEXPECTED
  unexpected_real = (unexpected_ptr)mProcs[77];
  mProcs[77] = (UINT_PTR)&unexpected_fake;
#endif
#ifdef WCSCHR
  wcschr_real = (wcschr_ptr)mProcs[78];
  mProcs[78] = (UINT_PTR)&wcschr_fake;
#endif
#ifdef WCSRCHR
  wcsrchr_real = (wcsrchr_ptr)mProcs[79];
  mProcs[79] = (UINT_PTR)&wcsrchr_fake;
#endif
#ifdef WCSSTR
  wcsstr_real = (wcsstr_ptr)mProcs[80];
  mProcs[80] = (UINT_PTR)&wcsstr_fake;
#endif
}
HMODULE base;


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	mHinst = hinstDLL;
	if (fdwReason == DLL_PROCESS_ATTACH) {
		WCHAR szPath[MAX_PATH];

		if (!GetSystemDirectoryW(szPath, sizeof(szPath) - 20))
			return FALSE;
		wcscat_s(szPath, L"\\vcruntime140.dll");

		mHinstDLL = LoadLibrary(szPath);
		if (!mHinstDLL) {
			return FALSE;
		}
		for (int i = 0; i < 81; ++i) {
			mProcs[i] = (UINT_PTR)GetProcAddress(mHinstDLL, mImportNames[i]);
		}
		_hook_setup();

		ULONG_PTR new_section_start = (ULONG_PTR)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READ);
		ULONG_PTR new_section_start2 = new_section_start + 6 + 10 + 5;

		base = GetModuleHandle(NULL);
		uint32_t addr_start = (uint32_t)base + 0xa0a1f + 5;
		uint32_t addr_start2 = (uint32_t)base + 0xa04c4 + 5;
		uint32_t addr_ret = (uint32_t)base + 0xa0A25;
		uint32_t addr_ret2 = (uint32_t)base + 0xa04ca;

		std::vector<BYTE> jmp_bytes = number_to_bytes(new_section_start - addr_start, sizeof(addr_start));
		std::vector<BYTE> jmp_bytes2 = number_to_bytes(new_section_start2 - addr_start2, sizeof(addr_start));
		std::vector<BYTE> addr_speed = number_to_bytes(0x13a600 + (uint32_t)base, sizeof(addr_start));
		RewriteMemoryEx(addr_start - 5, { 0xE9, jmp_bytes[0], jmp_bytes[1], jmp_bytes[2], jmp_bytes[3] });
		RewriteMemoryEx(addr_start2 - 5, { 0xE9, jmp_bytes2[0], jmp_bytes2[1], jmp_bytes2[2], jmp_bytes2[3] });
		std::vector<BYTE> ret_bytes_1 = number_to_bytes(addr_ret - (new_section_start2), sizeof(addr_start));
		std::vector<BYTE> ret_bytes_2 = number_to_bytes(addr_ret2 - (new_section_start2 + 6 + 10 + 5), sizeof(addr_start));
		std::vector<BYTE> code_bytes = { 0x8B, 0x4D, 0xFC,
			0x8B, 0x55, 0xFC,
			0xC7, 0x05, addr_speed[0], addr_speed[1], addr_speed[2], addr_speed[3], 0x15, 0x00, 0x00, 0x00,
			0xE9, ret_bytes_1[0], ret_bytes_1[1], ret_bytes_1[2], ret_bytes_1[3]
		};
		std::vector<BYTE> code_bytes2 = { 0x8B, 0x4D, 0xFC, 
			0x8B, 0x51, 0x08,
			0xC7, 0x05, addr_speed[0], addr_speed[1], addr_speed[2], addr_speed[3], 0x23, 0x00, 0x00, 0x00,
			0xE9, ret_bytes_2[0], ret_bytes_2[1], ret_bytes_2[2], ret_bytes_2[3]
		};
		RewriteMemoryEx(new_section_start, code_bytes);
		RewriteMemoryEx(new_section_start2, code_bytes2);
		
		
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
		FreeLibrary(mHinstDLL);
	}
	return TRUE;
}


extern "C" __declspec(naked) void __stdcall _CreateFrameInfo_wrapper(){
#ifdef _DEBUG
  log_info("calling _CreateFrameInfo");
#endif
  __asm{jmp mProcs[0 * 4]}
}
extern "C" __declspec(naked) void __stdcall _CxxThrowException_wrapper(){
#ifdef _DEBUG
  log_info("calling _CxxThrowException");
#endif
  __asm{jmp mProcs[1 * 4]}
}
extern "C" __declspec(naked) void __stdcall _EH_prolog_wrapper(){
#ifdef _DEBUG
  log_info("calling _EH_prolog");
#endif
  __asm{jmp mProcs[2 * 4]}
}
extern "C" __declspec(naked) void __stdcall _FindAndUnlinkFrame_wrapper(){
#ifdef _DEBUG
  log_info("calling _FindAndUnlinkFrame");
#endif
  __asm{jmp mProcs[3 * 4]}
}
extern "C" __declspec(naked) void __stdcall _IsExceptionObjectToBeDestroyed_wrapper(){
#ifdef _DEBUG
  log_info("calling _IsExceptionObjectToBeDestroyed");
#endif
  __asm{jmp mProcs[4 * 4]}
}
extern "C" __declspec(naked) void __stdcall _NLG_Dispatch2_wrapper(){
#ifdef _DEBUG
  log_info("calling _NLG_Dispatch2");
#endif
  __asm{jmp mProcs[5 * 4]}
}
extern "C" __declspec(naked) void __stdcall _NLG_Return_wrapper(){
#ifdef _DEBUG
  log_info("calling _NLG_Return");
#endif
  __asm{jmp mProcs[6 * 4]}
}
extern "C" __declspec(naked) void __stdcall _NLG_Return2_wrapper(){
#ifdef _DEBUG
  log_info("calling _NLG_Return2");
#endif
  __asm{jmp mProcs[7 * 4]}
}
extern "C" __declspec(naked) void __stdcall _SetWinRTOutOfMemoryExceptionCallback_wrapper(){
#ifdef _DEBUG
  log_info("calling _SetWinRTOutOfMemoryExceptionCallback");
#endif
  __asm{jmp mProcs[8 * 4]}
}
extern "C" __declspec(naked) void __stdcall __AdjustPointer_wrapper(){
#ifdef _DEBUG
  log_info("calling __AdjustPointer");
#endif
  __asm{jmp mProcs[9 * 4]}
}
extern "C" __declspec(naked) void __stdcall __BuildCatchObject_wrapper(){
#ifdef _DEBUG
  log_info("calling __BuildCatchObject");
#endif
  __asm{jmp mProcs[10 * 4]}
}
extern "C" __declspec(naked) void __stdcall __BuildCatchObjectHelper_wrapper(){
#ifdef _DEBUG
  log_info("calling __BuildCatchObjectHelper");
#endif
  __asm{jmp mProcs[11 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxDetectRethrow_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxDetectRethrow");
#endif
  __asm{jmp mProcs[12 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxExceptionFilter_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxExceptionFilter");
#endif
  __asm{jmp mProcs[13 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxFrameHandler_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxFrameHandler");
#endif
  __asm{jmp mProcs[14 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxFrameHandler2_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxFrameHandler2");
#endif
  __asm{jmp mProcs[15 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxFrameHandler3_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxFrameHandler3");
#endif
  __asm{jmp mProcs[16 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxLongjmpUnwind_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxLongjmpUnwind");
#endif
  __asm{jmp mProcs[17 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxQueryExceptionSize_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxQueryExceptionSize");
#endif
  __asm{jmp mProcs[18 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxRegisterExceptionObject_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxRegisterExceptionObject");
#endif
  __asm{jmp mProcs[19 * 4]}
}
extern "C" __declspec(naked) void __stdcall __CxxUnregisterExceptionObject_wrapper(){
#ifdef _DEBUG
  log_info("calling __CxxUnregisterExceptionObject");
#endif
  __asm{jmp mProcs[20 * 4]}
}
extern "C" __declspec(naked) void __stdcall __DestructExceptionObject_wrapper(){
#ifdef _DEBUG
  log_info("calling __DestructExceptionObject");
#endif
  __asm{jmp mProcs[21 * 4]}
}
extern "C" __declspec(naked) void __stdcall __FrameUnwindFilter_wrapper(){
#ifdef _DEBUG
  log_info("calling __FrameUnwindFilter");
#endif
  __asm{jmp mProcs[22 * 4]}
}
extern "C" __declspec(naked) void __stdcall __GetPlatformExceptionInfo_wrapper(){
#ifdef _DEBUG
  log_info("calling __GetPlatformExceptionInfo");
#endif
  __asm{jmp mProcs[23 * 4]}
}
extern "C" __declspec(naked) void __stdcall __RTCastToVoid_wrapper(){
#ifdef _DEBUG
  log_info("calling __RTCastToVoid");
#endif
  __asm{jmp mProcs[24 * 4]}
}
extern "C" __declspec(naked) void __stdcall __RTDynamicCast_wrapper(){
#ifdef _DEBUG
  log_info("calling __RTDynamicCast");
#endif
  __asm{jmp mProcs[25 * 4]}
}
extern "C" __declspec(naked) void __stdcall __RTtypeid_wrapper(){
#ifdef _DEBUG
  log_info("calling __RTtypeid");
#endif
  __asm{jmp mProcs[26 * 4]}
}
extern "C" __declspec(naked) void __stdcall __TypeMatch_wrapper(){
#ifdef _DEBUG
  log_info("calling __TypeMatch");
#endif
  __asm{jmp mProcs[27 * 4]}
}
extern "C" __declspec(naked) void __stdcall __current_exception_wrapper(){
#ifdef _DEBUG
  log_info("calling __current_exception");
#endif
  __asm{jmp mProcs[28 * 4]}
}
extern "C" __declspec(naked) void __stdcall __current_exception_context_wrapper(){
#ifdef _DEBUG
  log_info("calling __current_exception_context");
#endif
  __asm{jmp mProcs[29 * 4]}
}
extern "C" __declspec(naked) void __stdcall __intrinsic_setjmp_wrapper(){
#ifdef _DEBUG
  log_info("calling __intrinsic_setjmp");
#endif
  __asm{jmp mProcs[30 * 4]}
}
extern "C" __declspec(naked) void __stdcall __processing_throw_wrapper(){
#ifdef _DEBUG
  log_info("calling __processing_throw");
#endif
  __asm{jmp mProcs[31 * 4]}
}
extern "C" __declspec(naked) void __stdcall __report_gsfailure_wrapper(){
#ifdef _DEBUG
  log_info("calling __report_gsfailure");
#endif
  __asm{jmp mProcs[32 * 4]}
}
extern "C" __declspec(naked) void __stdcall __std_exception_copy_wrapper(){
#ifdef _DEBUG
  log_info("calling __std_exception_copy");
#endif
  __asm{jmp mProcs[33 * 4]}
}
extern "C" __declspec(naked) void __stdcall __std_exception_destroy_wrapper(){
#ifdef _DEBUG
  log_info("calling __std_exception_destroy");
#endif
  __asm{jmp mProcs[34 * 4]}
}
extern "C" __declspec(naked) void __stdcall __std_terminate_wrapper(){
#ifdef _DEBUG
  log_info("calling __std_terminate");
#endif
  __asm{jmp mProcs[35 * 4]}
}
extern "C" __declspec(naked) void __stdcall __std_type_info_compare_wrapper(){
#ifdef _DEBUG
  log_info("calling __std_type_info_compare");
#endif
  __asm{jmp mProcs[36 * 4]}
}
extern "C" __declspec(naked) void __stdcall __std_type_info_destroy_list_wrapper(){
#ifdef _DEBUG
  log_info("calling __std_type_info_destroy_list");
#endif
  __asm{jmp mProcs[37 * 4]}
}
extern "C" __declspec(naked) void __stdcall __std_type_info_hash_wrapper(){
#ifdef _DEBUG
  log_info("calling __std_type_info_hash");
#endif
  __asm{jmp mProcs[38 * 4]}
}
extern "C" __declspec(naked) void __stdcall __std_type_info_name_wrapper(){
#ifdef _DEBUG
  log_info("calling __std_type_info_name");
#endif
  __asm{jmp mProcs[39 * 4]}
}
extern "C" __declspec(naked) void __stdcall __telemetry_main_invoke_trigger_wrapper(){
#ifdef _DEBUG
  log_info("calling __telemetry_main_invoke_trigger");
#endif
  __asm{jmp mProcs[40 * 4]}
}
extern "C" __declspec(naked) void __stdcall __telemetry_main_return_trigger_wrapper(){
#ifdef _DEBUG
  log_info("calling __telemetry_main_return_trigger");
#endif
  __asm{jmp mProcs[41 * 4]}
}
extern "C" __declspec(naked) void __stdcall __unDName_wrapper(){
#ifdef _DEBUG
  log_info("calling __unDName");
#endif
  __asm{jmp mProcs[42 * 4]}
}
extern "C" __declspec(naked) void __stdcall __unDNameEx_wrapper(){
#ifdef _DEBUG
  log_info("calling __unDNameEx");
#endif
  __asm{jmp mProcs[43 * 4]}
}
extern "C" __declspec(naked) void __stdcall __uncaught_exception_wrapper(){
#ifdef _DEBUG
  log_info("calling __uncaught_exception");
#endif
  __asm{jmp mProcs[44 * 4]}
}
extern "C" __declspec(naked) void __stdcall __uncaught_exceptions_wrapper(){
#ifdef _DEBUG
  log_info("calling __uncaught_exceptions");
#endif
  __asm{jmp mProcs[45 * 4]}
}
extern "C" __declspec(naked) void __stdcall __vcrt_GetModuleFileNameW_wrapper(){
#ifdef _DEBUG
  log_info("calling __vcrt_GetModuleFileNameW");
#endif
  __asm{jmp mProcs[46 * 4]}
}
extern "C" __declspec(naked) void __stdcall __vcrt_GetModuleHandleW_wrapper(){
#ifdef _DEBUG
  log_info("calling __vcrt_GetModuleHandleW");
#endif
  __asm{jmp mProcs[47 * 4]}
}
extern "C" __declspec(naked) void __stdcall __vcrt_InitializeCriticalSectionEx_wrapper(){
#ifdef _DEBUG
  log_info("calling __vcrt_InitializeCriticalSectionEx");
#endif
  __asm{jmp mProcs[48 * 4]}
}
extern "C" __declspec(naked) void __stdcall __vcrt_LoadLibraryExW_wrapper(){
#ifdef _DEBUG
  log_info("calling __vcrt_LoadLibraryExW");
#endif
  __asm{jmp mProcs[49 * 4]}
}
extern "C" __declspec(naked) void __stdcall _chkesp_wrapper(){
#ifdef _DEBUG
  log_info("calling _chkesp");
#endif
  __asm{jmp mProcs[50 * 4]}
}
extern "C" __declspec(naked) void __stdcall _except_handler2_wrapper(){
#ifdef _DEBUG
  log_info("calling _except_handler2");
#endif
  __asm{jmp mProcs[51 * 4]}
}
extern "C" __declspec(naked) void __stdcall _except_handler3_wrapper(){
#ifdef _DEBUG
  log_info("calling _except_handler3");
#endif
  __asm{jmp mProcs[52 * 4]}
}
extern "C" __declspec(naked) void __stdcall _except_handler4_common_wrapper(){
#ifdef _DEBUG
  log_info("calling _except_handler4_common");
#endif
  __asm{jmp mProcs[53 * 4]}
}
extern "C" __declspec(naked) void __stdcall _get_purecall_handler_wrapper(){
#ifdef _DEBUG
  log_info("calling _get_purecall_handler");
#endif
  __asm{jmp mProcs[54 * 4]}
}
extern "C" __declspec(naked) void __stdcall _get_unexpected_wrapper(){
#ifdef _DEBUG
  log_info("calling _get_unexpected");
#endif
  __asm{jmp mProcs[55 * 4]}
}
extern "C" __declspec(naked) void __stdcall _global_unwind2_wrapper(){
#ifdef _DEBUG
  log_info("calling _global_unwind2");
#endif
  __asm{jmp mProcs[56 * 4]}
}
extern "C" __declspec(naked) void __stdcall _is_exception_typeof_wrapper(){
#ifdef _DEBUG
  log_info("calling _is_exception_typeof");
#endif
  __asm{jmp mProcs[57 * 4]}
}
extern "C" __declspec(naked) void __stdcall _local_unwind2_wrapper(){
#ifdef _DEBUG
  log_info("calling _local_unwind2");
#endif
  __asm{jmp mProcs[58 * 4]}
}
extern "C" __declspec(naked) void __stdcall _local_unwind4_wrapper(){
#ifdef _DEBUG
  log_info("calling _local_unwind4");
#endif
  __asm{jmp mProcs[59 * 4]}
}
extern "C" __declspec(naked) void __stdcall _longjmpex_wrapper(){
#ifdef _DEBUG
  log_info("calling _longjmpex");
#endif
  __asm{jmp mProcs[60 * 4]}
}
extern "C" __declspec(naked) void __stdcall _purecall_wrapper(){
#ifdef _DEBUG
  log_info("calling _purecall");
#endif
  __asm{jmp mProcs[61 * 4]}
}
extern "C" __declspec(naked) void __stdcall _seh_longjmp_unwind_wrapper(){
#ifdef _DEBUG
  log_info("calling _seh_longjmp_unwind");
#endif
  __asm{jmp mProcs[62 * 4]}
}
extern "C" __declspec(naked) void __stdcall _seh_longjmp_unwind4_wrapper(){
#ifdef _DEBUG
  log_info("calling _seh_longjmp_unwind4");
#endif
  __asm{jmp mProcs[63 * 4]}
}
extern "C" __declspec(naked) void __stdcall _set_purecall_handler_wrapper(){
#ifdef _DEBUG
  log_info("calling _set_purecall_handler");
#endif
  __asm{jmp mProcs[64 * 4]}
}
extern "C" __declspec(naked) void __stdcall _set_se_translator_wrapper(){
#ifdef _DEBUG
  log_info("calling _set_se_translator");
#endif
  __asm{jmp mProcs[65 * 4]}
}
extern "C" __declspec(naked) void __stdcall _setjmp3_wrapper(){
#ifdef _DEBUG
  log_info("calling _setjmp3");
#endif
  __asm{jmp mProcs[66 * 4]}
}
extern "C" __declspec(naked) void __stdcall longjmp_wrapper(){
#ifdef _DEBUG
  log_info("calling longjmp");
#endif
  __asm{jmp mProcs[67 * 4]}
}
extern "C" __declspec(naked) void __stdcall memchr_wrapper(){
#ifdef _DEBUG
  log_info("calling memchr");
#endif
  __asm{jmp mProcs[68 * 4]}
}
extern "C" __declspec(naked) void __stdcall memcmp_wrapper(){
#ifdef _DEBUG
  log_info("calling memcmp");
#endif
  __asm{jmp mProcs[69 * 4]}
}
extern "C" __declspec(naked) void __stdcall memcpy_wrapper(){
#ifdef _DEBUG
  log_info("calling memcpy");
#endif
  __asm{jmp mProcs[70 * 4]}
}
extern "C" __declspec(naked) void __stdcall memmove_wrapper(){
#ifdef _DEBUG
  log_info("calling memmove");
#endif
  __asm{jmp mProcs[71 * 4]}
}
extern "C" __declspec(naked) void __stdcall memset_wrapper(){
#ifdef _DEBUG
  log_info("calling memset");
#endif
  __asm{jmp mProcs[72 * 4]}
}
extern "C" __declspec(naked) void __stdcall set_unexpected_wrapper(){
#ifdef _DEBUG
  log_info("calling set_unexpected");
#endif
  __asm{jmp mProcs[73 * 4]}
}
extern "C" __declspec(naked) void __stdcall strchr_wrapper(){
#ifdef _DEBUG
  log_info("calling strchr");
#endif
  __asm{jmp mProcs[74 * 4]}
}
extern "C" __declspec(naked) void __stdcall strrchr_wrapper(){
#ifdef _DEBUG
  log_info("calling strrchr");
#endif
  __asm{jmp mProcs[75 * 4]}
}
extern "C" __declspec(naked) void __stdcall strstr_wrapper(){
#ifdef _DEBUG
  log_info("calling strstr");
#endif
  __asm{jmp mProcs[76 * 4]}
}
extern "C" __declspec(naked) void __stdcall unexpected_wrapper(){
#ifdef _DEBUG
  log_info("calling unexpected");
#endif
  __asm{jmp mProcs[77 * 4]}
}
extern "C" __declspec(naked) void __stdcall wcschr_wrapper(){
#ifdef _DEBUG
  log_info("calling wcschr");
#endif
  __asm{jmp mProcs[78 * 4]}
}
extern "C" __declspec(naked) void __stdcall wcsrchr_wrapper(){
#ifdef _DEBUG
  log_info("calling wcsrchr");
#endif
  __asm{jmp mProcs[79 * 4]}
}
extern "C" __declspec(naked) void __stdcall wcsstr_wrapper(){
#ifdef _DEBUG
  log_info("calling wcsstr");
#endif
  __asm{jmp mProcs[80 * 4]}
}
