/**
 *  Generator: vscode-decompiler@0.1.0 (https://marketplace.visualstudio.com/items?itemName=tintinweb.vscode-decompiler)
 *  Target:    "C:\\Users\\explora\\targets\\modern2\\modern2.exe"
 **/

/* Function: __mingw_invalidParameterHandler */
/* WARNING: Unknown calling convention */

void __mingw_invalidParameterHandler(wchar_t *expression, wchar_t *function, wchar_t *file, uint line, uintptr_t pReserved)

{
  return;
}

/* Function: pre_c_init */
/* WARNING: Unknown calling convention */

int pre_c_init(void)

{
  int *piVar1;
  PIMAGE_NT_HEADERS pPEHeader;

  managedapp = 0;
  *(undefined4 *)_refptr_mingw_initltsdrot_force = 1;
  *(undefined4 *)_refptr_mingw_initltsdyn_force = 1;
  *(undefined4 *)_refptr_mingw_initltssuo_force = 1;
  *(undefined4 *)_refptr_mingw_initcharmax = 1;
  if ((*(short *)_refptr___image_base__ == 0x5a4d) &&
      (piVar1 = (int *)(_refptr___image_base__ + *(int *)(_refptr___image_base__ + 0x3c)),
       *piVar1 == 0x4550))
  {
    if (*(short *)(piVar1 + 6) == 0x10b)
    {
      if (0xe < (uint)piVar1[0x1d])
      {
        managedapp = (int)(piVar1[0x3a] != 0);
      }
    }
    else if ((*(short *)(piVar1 + 6) == 0x20b) && (0xe < (uint)piVar1[0x21]))
    {
      managedapp = (int)(piVar1[0x3e] != 0);
    }
  }
  if (*(int *)_refptr_mingw_app_type == 0)
  {
    __set_app_type(1);
  }
  else
  {
    __set_app_type(2);
  }
  piVar1 = __p__fmode();
  *piVar1 = *(int *)_refptr__fmode;
  _setargv();
  if (*(int *)_refptr__MINGW_INSTALL_DEBUG_MATHERR != 1)
  {
    return 0;
  }
  __mingw_setusermatherr(_matherr);
  return 0;
}

/* Function: pre_cpp_init */
/* WARNING: Unknown calling convention */

void pre_cpp_init(void)

{
  startinfo.newmode = *(int *)_refptr__newmode;
  __getmainargs(&argc, &argv, &envp, *(undefined4 *)_refptr__dowildcard, &startinfo);
  return;
}

/* Function: __tmainCRTStartup */
/* WARNING: Unknown calling convention */

int __tmainCRTStartup(void)

{
  int iVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  undefined *puVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  char **ppcVar10;
  ulonglong ret;
  longlong lVar11;
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar12;
  char **ppcVar13;
  char **ppcVar14;
  char **n;
  size_t sVar15;
  char *pcVar16;
  longlong lVar17;
  ulonglong uVar18;
  void *fiberid;
  size_t l;
  LPSTARTUPINFOA p_Var19;
  char **avl;
  longlong unaff_GS_OFFSET;
  bool bVar20;
  STARTUPINFO StartupInfo;

  puVar9 = _refptr_mingw_app_type;
  p_Var19 = (LPSTARTUPINFOA)&StartupInfo;
  for (lVar17 = 0xd; lVar17 != 0; lVar17 = lVar17 + -1)
  {
    *(undefined8 *)p_Var19 = 0;
    p_Var19 = (LPSTARTUPINFOA)&p_Var19->lpReserved;
  }
  if (*(int *)_refptr_mingw_app_type != 0)
  {
    GetStartupInfoA((LPSTARTUPINFOA)&StartupInfo);
  }
  puVar5 = _refptr___native_startup_lock;
  lVar17 = *(longlong *)(*(longlong *)(unaff_GS_OFFSET + 0x30) + 8);
  while (true)
  {
    LOCK();
    lVar11 = *(longlong *)puVar5;
    if (lVar11 == 0)
    {
      *(longlong *)puVar5 = lVar17;
      lVar11 = 0;
    }
    puVar8 = _refptr___xi_z;
    puVar7 = _refptr___xi_a;
    puVar6 = _refptr___native_startup_state;
    UNLOCK();
    if (lVar11 == 0)
    {
      bVar20 = false;
      iVar4 = *(int *)_refptr___native_startup_state;
      goto joined_r0x00401411;
    }
    if (lVar17 == lVar11)
      break;
    Sleep(1000);
  }
  bVar20 = true;
  iVar4 = *(int *)_refptr___native_startup_state;
joined_r0x00401411:
  if (iVar4 == 1)
  {
    _amsg_exit(0x1f);
    iVar4 = *(int *)puVar6;
  }
  else
  {
    if (*(int *)_refptr___native_startup_state == 0)
    {
      *(undefined4 *)_refptr___native_startup_state = 1;
      _initterm(puVar7, puVar8);
    }
    else
    {
      has_cctor = 1;
    }
    iVar4 = *(int *)puVar6;
  }
  if (iVar4 == 1)
  {
    _initterm(_refptr___xc_a, _refptr___xc_z);
    *(undefined4 *)puVar6 = 2;
  }
  if (!bVar20)
  {
    LOCK();
    *(undefined8 *)puVar5 = 0;
    UNLOCK();
  }
  if (*(code **)_refptr___dyn_tls_init_callback != (code *)0x0)
  {
    (**(code **)_refptr___dyn_tls_init_callback)(0, 2, 0);
  }
  _pei386_runtime_relocator();
  pPVar12 = SetUnhandledExceptionFilter(_gnu_exception_handler);
  *(LPTOP_LEVEL_EXCEPTION_FILTER *)_refptr___mingw_oldexcpt_handler = pPVar12;
  __mingw_init_ehandler();
  mingw_set_invalid_parameter_handler(__mingw_invalidParameterHandler);
  _fpreset();
  __mingw_winmain_hInstance = (HINSTANCE)_refptr___image_base__;
  ppcVar13 = __p__acmdln();
  iVar4 = argc;
  bVar20 = false;
  pcVar16 = *ppcVar13;
  if (pcVar16 != (char *)0x0)
  {
    do
    {
      cVar3 = *pcVar16;
      if (cVar3 < '!')
      {
        __mingw_winmain_lpCmdLine = pcVar16;
        if (cVar3 == '\0')
          break;
        if (!bVar20)
          goto LAB_004012d0;
        bVar20 = true;
      }
      else if (cVar3 == '\"')
      {
        bVar20 = (bool)(bVar20 ^ 1);
      }
      pcVar16 = pcVar16 + 1;
    } while (true);
  }
  goto LAB_004012f0;
LAB_004012d0:
  if (cVar3 != '\0')
  {
    do
    {
      pcVar2 = pcVar16 + 1;
      pcVar16 = pcVar16 + 1;
      __mingw_winmain_lpCmdLine = pcVar16;
      if (*pcVar2 == '\0')
        break;
    } while (*pcVar2 < '!');
  }
LAB_004012f0:
  if ((*(int *)puVar9 != 0) && (__mingw_winmain_nShowCmd = 10, ((byte)StartupInfo.dwFlags & 1) != 0))
  {
    __mingw_winmain_nShowCmd = (DWORD)StartupInfo.wShowWindow;
  }
  iVar1 = argc + 1;
  ppcVar14 = (char **)malloc((longlong)iVar1 * 8);
  ppcVar10 = argv;
  ppcVar13 = ppcVar14;
  if (0 < iVar4)
  {
    uVar18 = 0;
    do
    {
      sVar15 = strlen(ppcVar10[uVar18]);
      pcVar16 = (char *)malloc(sVar15 + 1);
      ppcVar14[uVar18] = pcVar16;
      memcpy(pcVar16, ppcVar10[uVar18], sVar15 + 1);
      bVar20 = iVar4 - 1 != uVar18;
      uVar18 = uVar18 + 1;
    } while (bVar20);
    ppcVar13 = ppcVar14 + (longlong)iVar1 + -1;
  }
  *ppcVar13 = (char *)0x0;
  argv = ppcVar14;
  __main();
  iVar4 = argc;
  ppcVar13 = envp;
  **(undefined8 **)_refptr___imp___initenv = envp;
  mainret = main(iVar4, argv, ppcVar13);
  if (managedapp == 0)
  {
    /* WARNING: Subroutine does not return */
    exit(mainret);
  }
  if (has_cctor == 0)
  {
    _cexit();
    return mainret;
  }
  return mainret;
}

/* Function: WinMainCRTStartup */
/* WARNING: Unknown calling convention */

int WinMainCRTStartup(void)

{
  int iVar1;

  *(undefined4 *)_refptr_mingw_app_type = 1;
  __security_init_cookie();
  iVar1 = __tmainCRTStartup();
  return iVar1;
}

/* Function: mainCRTStartup */
/* WARNING: Unknown calling convention */

int mainCRTStartup(void)

{
  int iVar1;

  *(undefined4 *)_refptr_mingw_app_type = 0;
  __security_init_cookie();
  iVar1 = __tmainCRTStartup();
  return iVar1;
}

/* Function: atexit */
int __cdecl atexit(_func_5014 *param_1)

{
  _onexit_t p_Var1;

  p_Var1 = _onexit((_onexit_t)param_1);
  return -(uint)(p_Var1 == (_onexit_t)0x0);
}

/* Function: __gcc_register_frame */
void __gcc_register_frame(void)

{
  atexit(__gcc_deregister_frame);
  return;
}

/* Function: __gcc_deregister_frame */
void __gcc_deregister_frame(void)

{
  return;
}

/* Function: sanity_check */
undefined8 sanity_check(char *param_1)

{
  char *pcVar1;

  pcVar1 = strchr(param_1, 0x73);
  if (pcVar1 == (char *)0x0)
  {
    pcVar1 = strchr(param_1, 0x78);
    if (pcVar1 == (char *)0x0)
    {
      pcVar1 = strchr(param_1, 0x6e);
      if (pcVar1 == (char *)0x0)
      {
        pcVar1 = strchr(param_1, 0x53);
        if (pcVar1 == (char *)0x0)
        {
          pcVar1 = strchr(param_1, 0x58);
          if (pcVar1 == (char *)0x0)
          {
            pcVar1 = strchr(param_1, 0x4e);
            if (pcVar1 == (char *)0x0)
            {
              return 0;
            }
          }
        }
      }
    }
  }
  puts("NOT ALLOWED!");
  /* WARNING: Subroutine does not return */
  exit(1);
}

/* Function: main */
int __cdecl main(int _Argc, char **_Argv, char **_Env)

{
  char local_c8[112];
  char local_58[72];
  FILE *local_10;

  __main();
  local_10 = fopen("flag.txt", "r");
  if (local_10 == (FILE *)0x0)
  {
    puts("Something is wrong, please contact an admin!");
    /* WARNING: Subroutine does not return */
    exit(2);
  }
  fgets(local_58, 0x3c, local_10);
  puts("What\'s the secret ?");
  read(0, local_c8, 100);
  sanity_check(local_c8);
  printf(local_c8);
  puts("See u soon!");
  return 0;
}

/* Function: __do_global_dtors */
/* WARNING: Unknown calling convention */

void __do_global_dtors(void)

{
  func_ptr p_Var1;

  p_Var1 = *__do_global_dtors::p;
  while (p_Var1 != (func_ptr)0x0)
  {
    (*p_Var1)();
    p_Var1 = __do_global_dtors::p[1];
    __do_global_dtors::p = __do_global_dtors::p + 1;
  }
  return;
}

/* Function: __do_global_ctors */
/* WARNING: Unknown calling convention */

void __do_global_ctors(void)

{
  code **ppcVar1;
  ulong nptrs;
  ulonglong uVar2;
  ulong i;
  code **ppcVar3;

  i = (ulong) * (undefined8 *)_refptr___CTOR_LIST__;
  if (i == 0xffffffff)
  {
    uVar2 = 0;
    do
    {
      i = (ulong)uVar2;
      uVar2 = (ulonglong)(i + 1);
    } while (*(longlong *)(_refptr___CTOR_LIST__ + uVar2 * 8) != 0);
  }
  if (i != 0)
  {
    ppcVar3 = (code **)(_refptr___CTOR_LIST__ + (ulonglong)i * 8);
    ppcVar1 = (code **)(_refptr___CTOR_LIST__ + ((ulonglong)i - (ulonglong)(i - 1)) * 8 + -8);
    do
    {
      (**ppcVar3)();
      ppcVar3 = ppcVar3 + -1;
    } while (ppcVar3 != ppcVar1);
  }
  atexit(__do_global_dtors);
  return;
}

/* Function: __main */
/* WARNING: Unknown calling convention */

void __main(void)

{
  if (initialized != 0)
  {
    return;
  }
  initialized = 1;
  __do_global_ctors();
  return;
}

/* Function: my_lconv_init */
void my_lconv_init(void)

{
  /* WARNING: Could not recover jumptable at 0x00401790. Too many branches */
  /* WARNING: Treating indirect jump as call */
  __lconv_init();
  return;
}

/* Function: _setargv */
int __cdecl _setargv(void)

{
  return 0;
}

/* Function: __security_init_cookie */
void __cdecl __security_init_cookie(void)

{
  FT FVar1;
  DWORD DVar2;
  DWORD DVar3;
  DWORD DVar4;
  UINT_PTR cookie;
  FT systime;
  LARGE_INTEGER perfctr;

  systime.ft_scalar = 0;
  if (__security_cookie != 0x2b992ddfa232)
  {
    __security_cookie_complement = ~__security_cookie;
    return;
  }
  GetSystemTimeAsFileTime((LPFILETIME)&systime.ft_struct);
  FVar1 = systime;
  DVar2 = GetCurrentProcessId();
  DVar3 = GetCurrentThreadId();
  DVar4 = GetTickCount();
  QueryPerformanceCounter((LARGE_INTEGER *)&perfctr);
  __security_cookie =
      ((ulonglong)DVar4 ^ (ulonglong)DVar3 ^ (ulonglong)DVar2 ^ FVar1.ft_scalar ^ perfctr.QuadPart) & 0xffffffffffff;
  if (__security_cookie == 0x2b992ddfa232)
  {
    __security_cookie_complement = 0xffffd466d2205dcc;
    __security_cookie = 0x2b992ddfa233;
  }
  else
  {
    __security_cookie_complement = ~__security_cookie;
  }
  return;
}

/* Function: __report_gsfailure */
void __cdecl __report_gsfailure(uintptr_t _StackCookie)

{
  DWORD64 ControlPc;
  undefined *puVar1;
  DWORD64 DVar2;
  PRUNTIME_FUNCTION FunctionEntry;
  PRUNTIME_FUNCTION fctEntry;
  HANDLE hProcess;
  ULONG64 controlPC;
  DWORD64 unaff_retaddr;
  ULONG64 imgBase;
  ULONG64 establisherFrame;
  PVOID hndData;
  UINT_PTR cookie[2];

  RtlCaptureContext(&GS_ContextRecord);
  ControlPc = GS_ContextRecord.Rip;
  FunctionEntry = RtlLookupFunctionEntry(GS_ContextRecord.Rip, &imgBase, (PUNWIND_HISTORY_TABLE)0x0);
  puVar1 = &stack0xfffffffffffffff0;
  DVar2 = unaff_retaddr;
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0)
  {
    RtlVirtualUnwind(0, imgBase, ControlPc, FunctionEntry, (PCONTEXT)&GS_ContextRecord, &hndData,
                     &establisherFrame, (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    puVar1 = (undefined *)GS_ContextRecord.Rsp;
    DVar2 = GS_ContextRecord.Rip;
  }
  GS_ContextRecord.Rip = DVar2;
  GS_ContextRecord.Rsp = (DWORD64)puVar1;
  GS_ExceptionRecord.ExceptionAddress = (PVOID)GS_ContextRecord.Rip;
  GS_ExceptionRecord.ExceptionCode = 0xc0000409;
  GS_ExceptionRecord.ExceptionFlags = 1;
  cookie[0] = __security_cookie;
  cookie[1] = __security_cookie_complement;
  GS_ContextRecord.Rcx = _StackCookie;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&GS_ExceptionPointers);
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess, 0xc0000409);
  /* WARNING: Subroutine does not return */
  abort();
}

/* Function: __dyn_tls_dtor */
/* WARNING: Unknown calling convention */

BOOL __dyn_tls_dtor(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)

{
  if ((dwReason != 3) && (dwReason != 0))
  {
    return 1;
  }
  __mingw_TLScallback(hDllHandle, dwReason, lpreserved);
  return 1;
}

/* Function: __dyn_tls_init */
/* WARNING: Removing unreachable block (ram,0x00401a03) */
/* WARNING: Removing unreachable block (ram,0x00401a08) */
/* WARNING: Removing unreachable block (ram,0x00401a10) */
/* WARNING: Removing unreachable block (ram,0x00401a12) */
/* WARNING: Removing unreachable block (ram,0x00401a1b) */
/* WARNING: Unknown calling convention */

BOOL __dyn_tls_init(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)

{
  _PVFV *pfunc;

  if (*(int *)_refptr__CRT_MT != 2)
  {
    *(undefined4 *)_refptr__CRT_MT = 2;
  }
  if ((dwReason != 2) && (dwReason == 1))
  {
    __mingw_TLScallback(hDllHandle, 1, lpreserved);
    return 1;
  }
  return 1;
}

/* Function: __tlregdtor */
/* WARNING: Unknown calling convention */

int __tlregdtor(_PVFV func)

{
  return 0;
}

/* Function: _matherr */
int __cdecl _matherr(_exception *_Except)

{
  double dVar1;
  double dVar2;
  double dVar3;
  char *pcVar4;
  FILE *_File;
  char *type;

  switch (_Except->type)
  {
  default:
    type = "Unknown error";
    break;
  case 1:
    type = "Argument domain error (DOMAIN)";
    break;
  case 2:
    type = "Argument singularity (SIGN)";
    break;
  case 3:
    type = "Overflow range error (OVERFLOW)";
    break;
  case 4:
    type = "The result is too small to be represented (UNDERFLOW)";
    break;
  case 5:
    type = "Total loss of significance (TLOSS)";
    break;
  case 6:
    type = "Partial loss of significance (PLOSS)";
  }
  dVar1 = _Except->retval;
  dVar2 = _Except->arg2;
  dVar3 = _Except->arg1;
  pcVar4 = _Except->name;
  _File = __acrt_iob_func(2);
  fprintf((FILE *)_File, "_matherr(): %s in %s(%g, %g)  (retval=%g)\n", type, pcVar4, dVar3, dVar2, dVar1);
  return 0;
}

/* Function: _fpreset */
void __cdecl _fpreset(void)

{
  return;
}

/* Function: __report_error */
/* WARNING: Unknown calling convention */

void __report_error(char *msg, ...)

{
  FILE *pFVar1;
  undefined8 in_RDX;
  undefined8 in_R8;
  undefined8 in_R9;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  va_list argp;

  local_res10 = in_RDX;
  local_res18 = in_R8;
  local_res20 = in_R9;
  pFVar1 = __acrt_iob_func(2);
  fwrite("Mingw-w64 runtime failure:\n", 1, 0x1b, (FILE *)pFVar1);
  pFVar1 = __acrt_iob_func(2);
  vfprintf((FILE *)pFVar1, msg, (va_list)&local_res10);
  /* WARNING: Subroutine does not return */
  abort();
}

/* Function: __write_memory */
/* WARNING: Unknown calling convention */

void __write_memory(void *addr, void *src, size_t len)

{
  uint uVar1;
  BOOL BVar2;
  DWORD DVar3;
  PBYTE *ppBVar4;
  PIMAGE_SECTION_HEADER p_Var5;
  PIMAGE_SECTION_HEADER h;
  sSecInfo *psVar6;
  PBYTE pBVar7;
  SIZE_T SVar8;
  int iVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  uint uVar12;
  longlong lVar13;
  MEMORY_BASIC_INFORMATION b;

  lVar13 = (longlong)maxSections;
  if (maxSections < 1)
  {
    lVar13 = 0;
  }
  else
  {
    iVar9 = 0;
    ppBVar4 = &the_secs->sec_start;
    do
    {
      if ((*ppBVar4 <= addr) &&
          (addr < *ppBVar4 + (((PIMAGE_SECTION_HEADER)ppBVar4[1])->Misc).PhysicalAddress))
        goto LAB_00401cb7;
      iVar9 = iVar9 + 1;
      ppBVar4 = ppBVar4 + 5;
    } while (iVar9 != maxSections);
  }
  p_Var5 = __mingw_GetSectionForAddress(addr);
  if (p_Var5 == (PIMAGE_SECTION_HEADER)0x0)
  {
    /* WARNING: Subroutine does not return */
    __report_error("Address %p has no image-section", addr);
  }
  psVar6 = the_secs + lVar13;
  psVar6->hash = p_Var5;
  psVar6->old_protect = 0;
  pBVar7 = _GetPEImageBase();
  uVar12 = p_Var5->VirtualAddress;
  the_secs[lVar13].sec_start = pBVar7 + uVar12;
  SVar8 = VirtualQuery(pBVar7 + uVar12, (PMEMORY_BASIC_INFORMATION)&b, 0x30);
  if (SVar8 == 0)
  {
    /* WARNING: Subroutine does not return */
    __report_error("  VirtualQuery failed for %d bytes at address %p",
                   (ulonglong)(p_Var5->Misc).PhysicalAddress, the_secs[lVar13].sec_start);
  }
  if (((b.Protect - 0x40 & 0xffffffbf) != 0) && ((b.Protect - 4 & 0xfffffffb) != 0))
  {
    psVar6 = the_secs + lVar13;
    psVar6->base_address = b.BaseAddress;
    psVar6->region_size = b.RegionSize;
    BVar2 = VirtualProtect(b.BaseAddress, b.RegionSize, 0x40, &psVar6->old_protect);
    if (BVar2 == 0)
    {
      DVar3 = GetLastError();
      /* WARNING: Subroutine does not return */
      __report_error("  VirtualProtect failed with code 0x%x", (ulonglong)DVar3);
    }
  }
  maxSections = maxSections + 1;
LAB_00401cb7:
  uVar12 = (uint)len;
  if (uVar12 < 8)
  {
    if ((len & 4) == 0)
    {
      /* WARNING: Load size is inaccurate */
      if ((uVar12 != 0) && (*(undefined *)addr = *src, (len & 2) != 0))
      {
        *(undefined2 *)((longlong)addr + ((len & 0xffffffff) - 2)) =
            *(undefined2 *)((longlong)src + ((len & 0xffffffff) - 2));
      }
    }
    else
    {
      /* WARNING: Load size is inaccurate */
      *(undefined4 *)addr = *src;
      *(undefined4 *)((longlong)addr + ((len & 0xffffffff) - 4)) =
          *(undefined4 *)((longlong)src + ((len & 0xffffffff) - 4));
    }
  }
  else
  {
    /* WARNING: Load size is inaccurate */
    uVar10 = (longlong)addr + 8U & 0xfffffffffffffff8;
    *(undefined8 *)addr = *src;
    *(undefined8 *)((longlong)addr + ((len & 0xffffffff) - 8)) =
        *(undefined8 *)((longlong)src + ((len & 0xffffffff) - 8));
    lVar13 = (longlong)addr - uVar10;
    uVar12 = uVar12 + (int)lVar13 & 0xfffffff8;
    if (7 < uVar12)
    {
      uVar1 = 0;
      do
      {
        uVar11 = (ulonglong)uVar1;
        uVar1 = uVar1 + 8;
        *(undefined8 *)(uVar10 + uVar11) = *(undefined8 *)((longlong)src + (uVar11 - lVar13));
      } while (uVar1 < uVar12);
      return;
    }
  }
  return;
}

/* Function: _pei386_runtime_relocator */
/* WARNING: Function: ___chkstk_ms replaced with injection: alloca_probe */
/* WARNING: Unknown calling convention */

void _pei386_runtime_relocator(void)

{
  byte bVar1;
  ushort uVar2;
  DWORD flNewProtect;
  SIZE_T dwSize;
  LPVOID lpAddress;
  longlong lVar3;
  DWORD *pDVar4;
  DWORD *pDVar5;
  undefined *puVar6;
  int iVar7;
  int mSecs;
  uint uVar8;
  ptrdiff_t reloc_target;
  DWORD *pDVar9;
  ulonglong uVar10;
  longlong *addr;
  longlong *plVar11;
  runtime_pseudo_reloc_v2 *v2_hdr;
  runtime_pseudo_reloc_item_v2 *r;
  runtime_pseudo_reloc_v2 *prVar12;
  longlong lVar13;
  runtime_pseudo_reloc_item_v1 *o;
  ptrdiff_t addr_imp;
  undefined *puVar14;
  undefined8 auStack_80[6];
  ptrdiff_t reldata;

  if (_pei386_runtime_relocator::was_init != 0)
  {
    return;
  }
  _pei386_runtime_relocator::was_init = 1;
  auStack_80[0] = 0x401e37;
  iVar7 = __mingw_GetSectionCount();
  puVar6 = _refptr___image_base__;
  puVar14 = _refptr___RUNTIME_PSEUDO_RELOC_LIST_END__;
  auStack_80[0] = 0x401e4e;
  maxSections = 0;
  lVar3 = -((longlong)iVar7 * 0x28 + 0xfU & 0xfffffffffffffff0);
  the_secs = (sSecInfo *)((longlong)auStack_80 + lVar3 + 0x28);
  if ((longlong)_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ -
          (longlong)_refptr___RUNTIME_PSEUDO_RELOC_LIST__ <
      8)
  {
    maxSections = 0;
    return;
  }
  iVar7 = *(int *)_refptr___RUNTIME_PSEUDO_RELOC_LIST__;
  v2_hdr = (runtime_pseudo_reloc_v2 *)_refptr___RUNTIME_PSEUDO_RELOC_LIST__;
  if ((longlong)_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ -
          (longlong)_refptr___RUNTIME_PSEUDO_RELOC_LIST__ <
      0xc)
  {
  LAB_00401e8d:
    if (iVar7 == 0)
    {
      uVar8 = v2_hdr->magic2;
    LAB_00401e98:
      if (uVar8 == 0)
      {
        if (v2_hdr->version != 1)
        {
          /* WARNING: Subroutine does not return */
          *(undefined **)((longlong)auStack_80 + lVar3) = &UNK_004020d4;
          __report_error("  Unknown pseudo relocation protocol version %d.\n");
        }
        prVar12 = v2_hdr + 1;
        if (_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ <= prVar12)
        {
          maxSections = 0;
          return;
        }
        do
        {
          while (true)
          {
            bVar1 = *(byte *)&prVar12->version;
            plVar11 = (longlong *)(puVar6 + prVar12->magic1);
            addr = (longlong *)(puVar6 + prVar12->magic2);
            lVar13 = *plVar11;
            if (bVar1 != 0x20)
              break;
            uVar8 = *(uint *)addr;
            uVar10 = (ulonglong)uVar8 | 0xffffffff00000000;
            if (-1 < (int)uVar8)
            {
              uVar10 = (ulonglong)uVar8;
            }
            reldata = (uVar10 - (longlong)plVar11) + lVar13;
            *(undefined8 *)((longlong)auStack_80 + lVar3) = 0x40205a;
            __write_memory(addr, &reldata, 4);
          LAB_00401f00:
            prVar12 = prVar12 + 1;
            if (puVar14 <= prVar12)
              goto LAB_00401f80;
          }
          if (0x20 < bVar1)
          {
            if (bVar1 != 0x40)
            {
            LAB_004020b1:
              reldata = 0;
              /* WARNING: Subroutine does not return */
              *(undefined8 *)((longlong)auStack_80 + lVar3) = 0x4020c8;
              __report_error("  Unknown pseudo relocation bit size %d.\n", (ulonglong)bVar1);
            }
            reldata = (*addr - (longlong)plVar11) + lVar13;
            *(undefined8 *)((longlong)auStack_80 + lVar3) = 0x402028;
            __write_memory(addr, &reldata, 8);
            goto LAB_00401f00;
          }
          if (bVar1 == 8)
          {
            bVar1 = *(byte *)addr;
            uVar10 = (ulonglong)bVar1;
            if ((char)bVar1 < '\0')
            {
              uVar10 = (ulonglong)bVar1 | 0xffffffffffffff00;
            }
            reldata = (uVar10 - (longlong)plVar11) + lVar13;
            *(undefined8 *)((longlong)auStack_80 + lVar3) = 0x401f00;
            __write_memory(addr, &reldata, 1);
            goto LAB_00401f00;
          }
          if (bVar1 != 0x10)
            goto LAB_004020b1;
          uVar2 = *(ushort *)addr;
          uVar10 = (ulonglong)uVar2;
          if ((short)uVar2 < 0)
          {
            uVar10 = (ulonglong)uVar2 | 0xffffffffffff0000;
          }
          prVar12 = prVar12 + 1;
          reldata = (uVar10 - (longlong)plVar11) + lVar13;
          *(undefined8 *)((longlong)auStack_80 + lVar3) = 0x401f71;
          __write_memory(addr, &reldata, 2);
        } while (prVar12 < puVar14);
        goto LAB_00401f80;
      }
    }
  }
  else if (iVar7 == 0)
  {
    uVar8 = *(uint *)(_refptr___RUNTIME_PSEUDO_RELOC_LIST__ + 4);
    if ((uVar8 | *(uint *)(_refptr___RUNTIME_PSEUDO_RELOC_LIST__ + 8)) == 0)
    {
      iVar7 = *(int *)(_refptr___RUNTIME_PSEUDO_RELOC_LIST__ + 0xc);
      v2_hdr = (runtime_pseudo_reloc_v2 *)(_refptr___RUNTIME_PSEUDO_RELOC_LIST__ + 0xc);
      goto LAB_00401e8d;
    }
    goto LAB_00401e98;
  }
  if (_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ <= v2_hdr)
  {
    maxSections = 0;
    return;
  }
  puVar14 = _refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ + (-1 - (longlong)v2_hdr);
  pDVar4 = &v2_hdr->version;
  do
  {
    uVar8 = v2_hdr->magic2;
    pDVar5 = &v2_hdr->magic1;
    v2_hdr = (runtime_pseudo_reloc_v2 *)&v2_hdr->version;
    reldata = CONCAT44(reldata._4_4_, *pDVar5 + *(int *)(puVar6 + uVar8));
    *(undefined8 *)((longlong)auStack_80 + lVar3) = 0x4020a7;
    __write_memory(puVar6 + uVar8, &reldata, 4);
  } while (v2_hdr != (runtime_pseudo_reloc_v2 *)((longlong)pDVar4 + ((ulonglong)puVar14 & 0xfffffffffffffff8)));
LAB_00401f80:
  if (0 < maxSections)
  {
    lVar13 = 0;
    iVar7 = 0;
    do
    {
      pDVar9 = (DWORD *)((longlong)&the_secs->old_protect + lVar13);
      flNewProtect = *pDVar9;
      if (flNewProtect != 0)
      {
        dwSize = *(SIZE_T *)(pDVar9 + 4);
        lpAddress = *(LPVOID *)(pDVar9 + 2);
        *(undefined8 *)((longlong)auStack_80 + lVar3) = 0x401fc0;
        VirtualProtect(lpAddress, dwSize, flNewProtect, (PDWORD)&reldata);
      }
      iVar7 = iVar7 + 1;
      lVar13 = lVar13 + 0x28;
    } while (iVar7 < maxSections);
  }
  return;
}

/* Function: __mingw_raise_matherr */
/* WARNING: Unknown calling convention */

void __mingw_raise_matherr(int typ, char *name, double a1, double a2, double rslt)

{
  _exception ex;

  if (stUserMathErr != (fUserMathErr)0x0)
  {
    ex.retval = rslt;
    ex.type = typ;
    ex.name = name;
    ex.arg1 = a1;
    ex.arg2 = a2;
    (*stUserMathErr)(&ex);
  }
  return;
}

/* Function: __mingw_setusermatherr */
/* WARNING: Unknown calling convention */

void __mingw_setusermatherr(_func_int__exception_ptr *f)

{
  stUserMathErr = f;
  __setusermatherr();
  return;
}

/* Function: __mingw_SEH_error_handler */
/* WARNING: Unknown calling convention */

int __mingw_SEH_error_handler(_EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, _CONTEXT *ContextRecord,
                              void *DispatcherContext)

{
  uint uVar1;
  code *extraout_RAX;
  _func_void_int *old_handler;
  code *extraout_RAX_00;
  code *extraout_RAX_01;
  code *pcVar2;
  code *extraout_RAX_02;

  uVar1 = ExceptionRecord->ExceptionCode;
  if (0xc0000096 < uVar1)
  {
    return 1;
  }
  if (0xc000008b < uVar1)
  {
    switch (uVar1)
    {
    case 0xc000008d:
    case 0xc000008e:
    case 0xc000008f:
    case 0xc0000090:
    case 0xc0000091:
    case 0xc0000093:
      signal(8);
      pcVar2 = extraout_RAX;
      if (extraout_RAX != (code *)0x1)
        goto LAB_0040222d;
      signal(8);
      _fpreset();
    default:
      return 0;
    case 0xc0000094:
      signal(8);
      pcVar2 = extraout_RAX_01;
      if (extraout_RAX_01 == (code *)0x1)
      {
        signal(8);
        return 0;
      }
    LAB_0040222d:
      if (pcVar2 != (code *)0x0)
      {
        (*pcVar2)(8);
        return 0;
      }
      return 1;
    case 0xc0000096:
      goto switchD_00402170_caseD_c0000096;
    }
  }
  if (uVar1 == 0xc0000005)
  {
    signal(0xb);
    if (extraout_RAX_02 == (code *)0x1)
    {
      signal(0xb);
      return 0;
    }
    if (extraout_RAX_02 != (code *)0x0)
    {
      (*extraout_RAX_02)(0xb);
      return 0;
    }
  }
  else
  {
    if (uVar1 < 0xc0000006)
    {
      return (int)(uVar1 != 0x80000002);
    }
    if (uVar1 == 0xc0000008)
    {
      return 0;
    }
    if (uVar1 != 0xc000001d)
    {
      return 1;
    }
  switchD_00402170_caseD_c0000096:
    signal(4);
    if (extraout_RAX_00 == (code *)0x1)
    {
      signal(4);
      return 0;
    }
    if (extraout_RAX_00 != (code *)0x0)
    {
      (*extraout_RAX_00)(4);
      return 0;
    }
  }
  return 4;
}

/* Function: __mingw_init_ehandler */
/* WARNING: Unknown calling convention */

int __mingw_init_ehandler(void)

{
  DWORD DVar1;
  int iVar2;
  PBYTE BaseAddress;
  PBYTE _ImageBase;
  PIMAGE_SECTION_HEADER p_Var3;
  PIMAGE_SECTION_HEADER pSec;
  longlong lVar4;
  DWORD EntryCount;
  RUNTIME_FUNCTION *pRVar5;
  UNWIND_INFO *pUVar6;
  size_t eNo;

  BaseAddress = _GetPEImageBase();
  iVar2 = __mingw_init_ehandler::was_here;
  if ((__mingw_init_ehandler::was_here == 0) && (BaseAddress != (PBYTE)0x0))
  {
    __mingw_init_ehandler::was_here = 1;
    p_Var3 = _FindPESectionByName(".pdata");
    if (p_Var3 == (PIMAGE_SECTION_HEADER)0x0)
    {
      eNo = 0;
      pRVar5 = emu_pdata;
      for (lVar4 = 0x30; lVar4 != 0; lVar4 = lVar4 + -1)
      {
        pRVar5->BeginAddress = 0;
        pRVar5->EndAddress = 0;
        pRVar5 = (RUNTIME_FUNCTION *)&pRVar5->UnwindData;
      }
      pUVar6 = emu_xdata;
      for (lVar4 = 0x20; lVar4 != 0; lVar4 = lVar4 + -1)
      {
        pUVar6->VersionAndFlags = '\0';
        pUVar6->PrologSize = '\0';
        pUVar6->CountOfUnwindCodes = '\0';
        pUVar6->FrameRegisterAndOffset = '\0';
        pUVar6->AddressOfExceptionHandler = 0;
        pUVar6 = pUVar6 + 1;
      }
      pRVar5 = emu_pdata;
      pUVar6 = emu_xdata;
      do
      {
        p_Var3 = _FindPESectionExec(eNo);
        if (p_Var3 == (PIMAGE_SECTION_HEADER)0x0)
        {
          if (eNo == 0)
            goto LAB_0040233c;
          EntryCount = (DWORD)eNo;
          goto LAB_004023e5;
        }
        pUVar6->VersionAndFlags = '\t';
        eNo = eNo + 1;
        pUVar6->AddressOfExceptionHandler = 0x402140 - (int)BaseAddress;
        DVar1 = p_Var3->VirtualAddress;
        pRVar5->BeginAddress = DVar1;
        pRVar5->EndAddress = DVar1 + (p_Var3->Misc).PhysicalAddress;
        pRVar5->UnwindData = (int)pUVar6 - (int)BaseAddress;
        pRVar5 = pRVar5 + 1;
        pUVar6 = pUVar6 + 1;
      } while (eNo != 0x20);
      EntryCount = 0x20;
    LAB_004023e5:
      RtlAddFunctionTable((PRUNTIME_FUNCTION)emu_pdata, EntryCount, (DWORD64)BaseAddress);
    }
  LAB_0040233c:
    iVar2 = 1;
  }
  return iVar2;
}

/* Function: _gnu_exception_handler */
/* WARNING: Unknown calling convention */

long _gnu_exception_handler(EXCEPTION_POINTERS *exception_data)

{
  uint uVar1;
  LONG LVar2;
  code *extraout_RAX;
  _func_void_int *old_handler;
  code *extraout_RAX_00;
  code *extraout_RAX_01;
  code *pcVar3;
  code *extraout_RAX_02;

  uVar1 = exception_data->ExceptionRecord->ExceptionCode;
  if (((uVar1 & 0x20ffffff) == 0x20474343) &&
      ((*(byte *)&exception_data->ExceptionRecord->ExceptionFlags & 1) == 0))
  {
    return -1;
  }
  if (0xc0000096 < uVar1)
    goto LAB_004024d7;
  if (uVar1 < 0xc000008c)
  {
    if (uVar1 == 0xc0000005)
    {
      signal(0xb);
      if (extraout_RAX_02 == (code *)0x1)
      {
        signal(0xb);
        return -1;
      }
      if (extraout_RAX_02 != (code *)0x0)
      {
        (*extraout_RAX_02)(0xb);
        return -1;
      }
      goto LAB_004024d7;
    }
    if (uVar1 < 0xc0000006)
    {
      if (uVar1 == 0x80000002)
      {
        return -1;
      }
      goto LAB_004024d7;
    }
    if (uVar1 == 0xc0000008)
    {
      return -1;
    }
    if (uVar1 != 0xc000001d)
      goto LAB_004024d7;
  switchD_0040244c_caseD_c0000096:
    signal(4);
    if (extraout_RAX_00 == (code *)0x1)
    {
      signal(4);
    }
    else
    {
      if (extraout_RAX_00 == (code *)0x0)
        goto LAB_004024d7;
      (*extraout_RAX_00)(4);
    }
  }
  else
  {
    switch (uVar1)
    {
    case 0xc000008d:
    case 0xc000008e:
    case 0xc000008f:
    case 0xc0000090:
    case 0xc0000091:
    case 0xc0000093:
      signal(8);
      pcVar3 = extraout_RAX;
      if (extraout_RAX == (code *)0x1)
      {
        signal(8);
        _fpreset();
        return -1;
      }
      break;
    default:
      goto LAB_0040247d;
    case 0xc0000094:
      signal(8);
      pcVar3 = extraout_RAX_01;
      if (extraout_RAX_01 == (code *)0x1)
      {
        signal(8);
        return -1;
      }
      break;
    case 0xc0000096:
      goto switchD_0040244c_caseD_c0000096;
    }
    if (pcVar3 == (code *)0x0)
    {
    LAB_004024d7:
      if (__mingw_oldexcpt_handler == (LPTOP_LEVEL_EXCEPTION_FILTER)0x0)
      {
        return 0;
      }
      /* WARNING: Could not recover jumptable at 0x004024ec. Too many branches */
      /* WARNING: Treating indirect jump as call */
      LVar2 = (*__mingw_oldexcpt_handler)(exception_data);
      return LVar2;
    }
    (*pcVar3)(8);
  }
LAB_0040247d:
  return -1;
}

/* Function: __mingwthr_run_key_dtors */
/* WARNING: Unknown calling convention */

void __mingwthr_run_key_dtors(void)

{
  __mingwthr_key_t *p_Var1;
  LPVOID pvVar2;
  LPVOID value;
  __mingwthr_key_t *keyp;

  EnterCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  for (p_Var1 = key_dtor_list; p_Var1 != (__mingwthr_key_t *)0x0; p_Var1 = p_Var1->next)
  {
    pvVar2 = TlsGetValue(p_Var1->key);
    value._0_4_ = GetLastError();
    if (((DWORD)value == 0) && (pvVar2 != (LPVOID)0x0))
    {
      (*p_Var1->dtor)(pvVar2);
    }
  }
  /* WARNING: Could not recover jumptable at 0x00402614. Too many branches */
  /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  return;
}

/* Function: ___w64_mingwthr_add_key_dtor */
/* WARNING: Unknown calling convention */

int ___w64_mingwthr_add_key_dtor(DWORD key, _func_void_void_ptr *dtor)

{
  int iVar1;
  __mingwthr_key_t *p_Var2;
  __mingwthr_key_t *new_key;

  iVar1 = __mingwthr_cs_init;
  if (__mingwthr_cs_init != 0)
  {
    p_Var2 = (__mingwthr_key_t *)calloc(1, 0x18);
    if (p_Var2 != (__mingwthr_key_t *)0x0)
    {
      p_Var2->key = key;
      p_Var2->dtor = dtor;
      EnterCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
      p_Var2->next = key_dtor_list;
      key_dtor_list = p_Var2;
      LeaveCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
      return 0;
    }
    iVar1 = -1;
  }
  return iVar1;
}

/* Function: ___w64_mingwthr_remove_key_dtor */
/* WARNING: Unknown calling convention */

int ___w64_mingwthr_remove_key_dtor(DWORD key)

{
  __mingwthr_key_t *p_Var1;
  __mingwthr_key_t *cur_key;
  __mingwthr_key_t *_Memory;
  __mingwthr_key_t *p_Var2;

  if (__mingwthr_cs_init == 0)
  {
    return 0;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  if (key_dtor_list != (__mingwthr_key_t *)0x0)
  {
    p_Var1 = key_dtor_list;
    p_Var2 = (__mingwthr_key_t *)0x0;
    do
    {
      _Memory = p_Var1;
      p_Var1 = _Memory->next;
      if (_Memory->key == key)
      {
        if (p_Var2 != (__mingwthr_key_t *)0x0)
        {
          p_Var2->next = p_Var1;
          p_Var1 = key_dtor_list;
        }
        key_dtor_list = p_Var1;
        free(_Memory);
        break;
      }
      p_Var2 = _Memory;
    } while (p_Var1 != (__mingwthr_key_t *)0x0);
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  return 0;
}

/* Function: __mingw_TLScallback */
/* WARNING: Unknown calling convention */

WINBOOL __mingw_TLScallback(HANDLE hDllHandle, DWORD reason, LPVOID reserved)

{
  __mingwthr_key_t *p_Var1;
  __mingwthr_key_t *_Memory;
  __mingwthr_key_t *keyp;
  __mingwthr_key_t *t;

  if (reason != 2)
  {
    if (reason < 3)
    {
      if (reason == 0)
      {
        if (__mingwthr_cs_init != 0)
        {
          __mingwthr_run_key_dtors();
        }
        if (__mingwthr_cs_init == 1)
        {
          __mingwthr_cs_init = 1;
          _Memory = key_dtor_list;
          while (_Memory != (__mingwthr_key_t *)0x0)
          {
            p_Var1 = _Memory->next;
            free(_Memory);
            _Memory = p_Var1;
          }
          key_dtor_list = (__mingwthr_key_t *)0x0;
          __mingwthr_cs_init = 0;
          DeleteCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
        }
      }
      else
      {
        if (__mingwthr_cs_init == 0)
        {
          InitializeCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
        }
        __mingwthr_cs_init = 1;
      }
    }
    else if ((reason == 3) && (__mingwthr_cs_init != 0))
    {
      __mingwthr_run_key_dtors();
    }
    return 1;
  }
  _fpreset();
  return 1;
}

/* Function: _ValidateImageBase */
BOOL __cdecl _ValidateImageBase(PBYTE pImageBase)

{
  uint uVar1;
  PIMAGE_NT_HEADERS pNTHeader;

  uVar1 = 0;
  if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)
  {
    uVar1 = (uint)(*(short *)((longlong)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x20b);
  }
  return uVar1;
}

/* Function: _ValidateImageBase */
/* Local variable pDOSHeader:PIMAGE_DOS_HEADER[RCX:8] conflicts with parameter, skipped. */

BOOL __cdecl _ValidateImageBase(PBYTE pImageBase)

{
  BOOL BVar1;

  if (*(short *)pImageBase == 0x5a4d)
  {
    BVar1 = _ValidateImageBase(pImageBase);
    return BVar1;
  }
  return 0;
}

/* Function: _FindPESection */
PIMAGE_SECTION_HEADER __cdecl _FindPESection(PBYTE pImageBase, DWORD_PTR rva)

{
  PIMAGE_SECTION_HEADER p_Var1;
  int iVar2;
  PIMAGE_SECTION_HEADER pSection;
  PIMAGE_SECTION_HEADER p_Var3;
  PIMAGE_NT_HEADERS pNTHeader;

  iVar2 = *(int *)(pImageBase + 0x3c);
  p_Var3 = (PIMAGE_SECTION_HEADER)(pImageBase +
                                   (ulonglong) * (ushort *)(pImageBase + (longlong)iVar2 + 0x14) + (longlong)iVar2 + 0x18);
  if (*(ushort *)(pImageBase + (longlong)iVar2 + 6) != 0)
  {
    p_Var1 = p_Var3 + (ulonglong)(*(ushort *)(pImageBase + (longlong)iVar2 + 6) - 1) + 1;
    do
    {
      if ((p_Var3->VirtualAddress <= rva) &&
          (rva < p_Var3->VirtualAddress + (p_Var3->Misc).PhysicalAddress))
      {
        return p_Var3;
      }
      p_Var3 = p_Var3 + 1;
    } while (p_Var3 != p_Var1);
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}

/* Function: _FindPESectionByName */
/* WARNING: Unknown calling convention */

PIMAGE_SECTION_HEADER _FindPESectionByName(char *pName)

{
  PIMAGE_SECTION_HEADER p_Var1;
  BOOL BVar2;
  int iVar3;
  size_t sVar4;
  undefined *puVar5;
  PIMAGE_NT_HEADERS pNTHeader;
  PIMAGE_SECTION_HEADER pSection;
  PIMAGE_SECTION_HEADER _Str1;

  sVar4 = strlen(pName);
  if (8 < sVar4)
  {
    return (PIMAGE_SECTION_HEADER)0x0;
  }
  if ((*(short *)_refptr___image_base__ == 0x5a4d) &&
      (puVar5 = _refptr___image_base__, BVar2 = _ValidateImageBase(_refptr___image_base__),
       BVar2 != 0))
  {
    iVar3 = *(int *)(puVar5 + 0x3c);
    _Str1 = (PIMAGE_SECTION_HEADER)(puVar5 + (ulonglong) * (ushort *)(puVar5 + (longlong)iVar3 + 0x14) +
                                    (longlong)iVar3 + 0x18);
    if (*(ushort *)(puVar5 + (longlong)iVar3 + 6) == 0)
    {
      return (PIMAGE_SECTION_HEADER)0x0;
    }
    p_Var1 = _Str1 + (ulonglong)(*(ushort *)(puVar5 + (longlong)iVar3 + 6) - 1) + 1;
    do
    {
      iVar3 = strncmp((char *)_Str1, pName, 8);
      if (iVar3 == 0)
      {
        return _Str1;
      }
      _Str1 = _Str1 + 1;
    } while (_Str1 != p_Var1);
    return (PIMAGE_SECTION_HEADER)0x0;
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}

/* Function: __mingw_GetSectionForAddress */
/* WARNING: Unknown calling convention */

PIMAGE_SECTION_HEADER __mingw_GetSectionForAddress(LPVOID p)

{
  PIMAGE_SECTION_HEADER p_Var1;
  int iVar2;
  BOOL BVar3;
  DWORD_PTR rva;
  PIMAGE_SECTION_HEADER p_Var4;
  PIMAGE_SECTION_HEADER pSection;
  undefined *puVar5;
  PIMAGE_NT_HEADERS pNTHeader;

  p_Var4 = (PIMAGE_SECTION_HEADER)0x0;
  if ((*(short *)_refptr___image_base__ == 0x5a4d) &&
      (puVar5 = _refptr___image_base__, BVar3 = _ValidateImageBase(_refptr___image_base__),
       BVar3 != 0))
  {
    iVar2 = *(int *)(puVar5 + 0x3c);
    p_Var4 = (PIMAGE_SECTION_HEADER)(puVar5 + (ulonglong) * (ushort *)(puVar5 + (longlong)iVar2 + 0x14) +
                                     (longlong)iVar2 + 0x18);
    if (*(ushort *)(puVar5 + (longlong)iVar2 + 6) != 0)
    {
      p_Var1 = p_Var4 + (ulonglong)(*(ushort *)(puVar5 + (longlong)iVar2 + 6) - 1) + 1;
      do
      {
        if (((ulonglong)p_Var4->VirtualAddress <= (ulonglong)((longlong)p - (longlong)puVar5)) &&
            ((ulonglong)((longlong)p - (longlong)puVar5) <
             (ulonglong)(p_Var4->VirtualAddress + (p_Var4->Misc).PhysicalAddress)))
        {
          return p_Var4;
        }
        p_Var4 = p_Var4 + 1;
      } while (p_Var4 != p_Var1);
    }
    p_Var4 = (PIMAGE_SECTION_HEADER)0x0;
  }
  return p_Var4;
}

/* Function: __mingw_GetSectionCount */
/* WARNING: Unknown calling convention */

int __mingw_GetSectionCount(void)

{
  uint uVar1;
  undefined *puVar2;

  uVar1 = 0;
  if (*(short *)_refptr___image_base__ == 0x5a4d)
  {
    puVar2 = _refptr___image_base__;
    uVar1 = _ValidateImageBase(_refptr___image_base__);
    if (uVar1 != 0)
    {
      uVar1 = (uint) * (ushort *)(puVar2 + (longlong) * (int *)(puVar2 + 0x3c) + 6);
    }
  }
  return uVar1;
}

/* Function: _FindPESectionExec */
/* WARNING: Unknown calling convention */

PIMAGE_SECTION_HEADER _FindPESectionExec(size_t eNo)

{
  PIMAGE_SECTION_HEADER p_Var1;
  int iVar2;
  BOOL BVar3;
  undefined *puVar4;
  PIMAGE_NT_HEADERS pNTHeader;
  PIMAGE_SECTION_HEADER p_Var5;
  PIMAGE_SECTION_HEADER pSection;

  p_Var5 = (PIMAGE_SECTION_HEADER)0x0;
  if ((*(short *)_refptr___image_base__ == 0x5a4d) &&
      (puVar4 = _refptr___image_base__, BVar3 = _ValidateImageBase(_refptr___image_base__),
       BVar3 != 0))
  {
    iVar2 = *(int *)(puVar4 + 0x3c);
    p_Var5 = (PIMAGE_SECTION_HEADER)(puVar4 + (ulonglong) * (ushort *)(puVar4 + (longlong)iVar2 + 0x14) +
                                     (longlong)iVar2 + 0x18);
    if (*(ushort *)(puVar4 + (longlong)iVar2 + 6) != 0)
    {
      p_Var1 = p_Var5 + (ulonglong)(*(ushort *)(puVar4 + (longlong)iVar2 + 6) - 1) + 1;
      do
      {
        if ((*(byte *)((longlong)&p_Var5->Characteristics + 3) & 0x20) != 0)
        {
          if (eNo == 0)
          {
            return p_Var5;
          }
          eNo = eNo - 1;
        }
        p_Var5 = p_Var5 + 1;
      } while (p_Var5 != p_Var1);
    }
    p_Var5 = (PIMAGE_SECTION_HEADER)0x0;
  }
  return p_Var5;
}

/* Function: _GetPEImageBase */
/* WARNING: Unknown calling convention */

PBYTE _GetPEImageBase(void)

{
  BOOL BVar1;
  PBYTE pBVar2;
  PBYTE pBVar3;

  pBVar3 = (PBYTE)0x0;
  if (*(short *)_refptr___image_base__ == 0x5a4d)
  {
    pBVar2 = _refptr___image_base__;
    BVar1 = _ValidateImageBase(_refptr___image_base__);
    if (BVar1 != 0)
    {
      pBVar3 = pBVar2;
    }
  }
  return pBVar3;
}

/* Function: _IsNonwritableInCurrentImage */
BOOL __cdecl _IsNonwritableInCurrentImage(PBYTE pTarget)

{
  undefined *puVar1;
  int iVar2;
  BOOL BVar3;
  PIMAGE_SECTION_HEADER pSection_1;
  undefined *puVar4;
  PIMAGE_SECTION_HEADER pSection;
  DWORD_PTR rvaTarget;
  undefined *puVar5;
  PIMAGE_NT_HEADERS pNTHeader;

  BVar3 = 0;
  if (*(short *)_refptr___image_base__ == 0x5a4d)
  {
    puVar5 = _refptr___image_base__;
    BVar3 = _ValidateImageBase(_refptr___image_base__);
    if (BVar3 != 0)
    {
      iVar2 = *(int *)(puVar5 + 0x3c);
      puVar4 = puVar5 + (ulonglong) * (ushort *)(puVar5 + (longlong)iVar2 + 0x14) +
               (longlong)iVar2 + 0x18;
      if (*(ushort *)(puVar5 + (longlong)iVar2 + 6) != 0)
      {
        puVar1 = puVar4 + (ulonglong)(*(ushort *)(puVar5 + (longlong)iVar2 + 6) - 1) * 0x28 + 0x28;
        do
        {
          if (((ulonglong) * (uint *)(puVar4 + 0xc) <=
               (ulonglong)((longlong)pTarget - (longlong)puVar5)) &&
              ((ulonglong)((longlong)pTarget - (longlong)puVar5) <
               (ulonglong)(*(uint *)(puVar4 + 0xc) + *(int *)(puVar4 + 8))))
          {
            return ~*(uint *)(puVar4 + 0x24) >> 0x1f;
          }
          puVar4 = puVar4 + 0x28;
        } while (puVar4 != puVar1);
      }
      BVar3 = 0;
    }
  }
  return BVar3;
}

/* Function: __mingw_enum_import_library_names */
/* WARNING: Unknown calling convention */

char *__mingw_enum_import_library_names(int i)

{
  undefined *puVar1;
  int iVar2;
  BOOL BVar3;
  DWORD importsStartRVA;
  ulonglong uVar4;
  PIMAGE_IMPORT_DESCRIPTOR importDesc;
  PIMAGE_NT_HEADERS pNTHeader;
  PIMAGE_NT_HEADERS pNTHeader_1;
  PIMAGE_SECTION_HEADER pSection;
  undefined *puVar5;
  ulonglong uVar6;
  char *pcVar7;
  undefined *puVar8;

  pcVar7 = (char *)0x0;
  uVar6 = (ulonglong)(uint)i;
  if (*(short *)_refptr___image_base__ == 0x5a4d)
  {
    puVar8 = _refptr___image_base__;
    BVar3 = _ValidateImageBase(_refptr___image_base__);
    if (BVar3 != 0)
    {
      iVar2 = *(int *)(puVar8 + 0x3c);
      uVar4 = (ulonglong) * (uint *)(puVar8 + (longlong)iVar2 + 0x90);
      if (*(uint *)(puVar8 + (longlong)iVar2 + 0x90) != 0)
      {
        puVar5 = puVar8 + (ulonglong) * (ushort *)(puVar8 + (longlong)iVar2 + 0x14) +
                 (longlong)iVar2 + 0x18;
        if (*(ushort *)(puVar8 + (longlong)iVar2 + 6) != 0)
        {
          puVar1 = puVar5 + (ulonglong)(*(ushort *)(puVar8 + (longlong)iVar2 + 6) - 1) * 0x28 + 0x28;
          while ((uVar4 < *(uint *)(puVar5 + 0xc) ||
                  (*(uint *)(puVar5 + 0xc) + *(int *)(puVar5 + 8) <= uVar4)))
          {
            puVar5 = puVar5 + 0x28;
            if (puVar5 == puVar1)
              goto LAB_00402ba5;
          }
          for (puVar5 = puVar8 + uVar4; (*(int *)(puVar5 + 4) != 0 || (*(int *)(puVar5 + 0xc) != 0)); puVar5 = puVar5 + 0x14)
          {
            if ((int)uVar6 < 1)
            {
              return puVar8 + *(uint *)(puVar5 + 0xc);
            }
            uVar6 = (ulonglong)((int)uVar6 - 1);
          }
        LAB_00402ba5:
          pcVar7 = (char *)0x0;
        }
      }
    }
  }
  return pcVar7;
}

/* Function: ___chkstk_ms */
/* WARNING: This is an inlined function */

ulonglong ___chkstk_ms(void)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 local_res8[4];
  ulonglong uStack_10;

  puVar2 = local_res8;
  uVar1 = in_RAX;
  if (0xfff < in_RAX)
  {
    do
    {
      puVar2 = puVar2 + -0x200;
      *puVar2 = *puVar2;
      uVar1 = uVar1 - 0x1000;
    } while (0x1000 < uVar1);
  }
  uStack_10 = in_RAX;
  *(undefined8 *)((longlong)puVar2 - uVar1) = *(undefined8 *)((longlong)puVar2 - uVar1);
  return uStack_10;
}

/* Function: read */
int __cdecl read(int _FileHandle, void *_DstBuf, uint _MaxCharCount)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c30. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = _read(_FileHandle, _DstBuf, _MaxCharCount);
  return iVar1;
}

/* Function: vfprintf */
int __cdecl vfprintf(FILE *_File, char *_Format, va_list _ArgList)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c38. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = vfprintf(_File, _Format, _ArgList);
  return iVar1;
}

/* Function: strncmp */
int __cdecl strncmp(char *_Str1, char *_Str2, size_t _MaxCount)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c40. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = strncmp(_Str1, _Str2, _MaxCount);
  return iVar1;
}

/* Function: strlen */
size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;

  /* WARNING: Could not recover jumptable at 0x00402c48. Too many branches */
  /* WARNING: Treating indirect jump as call */
  sVar1 = strlen(_Str);
  return sVar1;
}

/* Function: strchr */
char *__cdecl strchr(char *_Str, int _Val)

{
  char *pcVar1;

  /* WARNING: Could not recover jumptable at 0x00402c50. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pcVar1 = strchr(_Str, _Val);
  return pcVar1;
}

/* Function: signal */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void signal(int param_1)

{
  /* WARNING: Could not recover jumptable at 0x00402c58. Too many branches */
  /* WARNING: Treating indirect jump as call */
  signal(param_1);
  return;
}

/* Function: puts */
int __cdecl puts(char *_Str)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c60. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = puts(_Str);
  return iVar1;
}

/* Function: printf */
int __cdecl printf(char *_Format, ...)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c68. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = printf(_Format);
  return iVar1;
}

/* Function: memcpy */
void *__cdecl memcpy(void *_Dst, void *_Src, size_t _Size)

{
  void *pvVar1;

  /* WARNING: Could not recover jumptable at 0x00402c70. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pvVar1 = memcpy(_Dst, _Src, _Size);
  return pvVar1;
}

/* Function: malloc */
void *__cdecl malloc(size_t _Size)

{
  void *pvVar1;

  /* WARNING: Could not recover jumptable at 0x00402c78. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pvVar1 = malloc(_Size);
  return pvVar1;
}

/* Function: fwrite */
size_t __cdecl fwrite(void *_Str, size_t _Size, size_t _Count, FILE *_File)

{
  size_t sVar1;

  /* WARNING: Could not recover jumptable at 0x00402c80. Too many branches */
  /* WARNING: Treating indirect jump as call */
  sVar1 = fwrite(_Str, _Size, _Count, _File);
  return sVar1;
}

/* Function: free */
void __cdecl free(void *_Memory)

{
  /* WARNING: Could not recover jumptable at 0x00402c88. Too many branches */
  /* WARNING: Treating indirect jump as call */
  free(_Memory);
  return;
}

/* Function: fprintf */
int __cdecl fprintf(FILE *_File, char *_Format, ...)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c90. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = fprintf(_File, _Format);
  return iVar1;
}

/* Function: fopen */
FILE *__cdecl fopen(char *_Filename, char *_Mode)

{
  FILE *pFVar1;

  /* WARNING: Could not recover jumptable at 0x00402c98. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pFVar1 = fopen(_Filename, _Mode);
  return pFVar1;
}

/* Function: fgets */
char *__cdecl fgets(char *_Buf, int _MaxCount, FILE *_File)

{
  char *pcVar1;

  /* WARNING: Could not recover jumptable at 0x00402ca0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pcVar1 = fgets(_Buf, _MaxCount, _File);
  return pcVar1;
}

/* Function: exit */
void __cdecl exit(int _Code)

{
  /* WARNING: Could not recover jumptable at 0x00402ca8. Too many branches */
  /* WARNING: Subroutine does not return */
  /* WARNING: Treating indirect jump as call */
  exit(_Code);
  return;
}

/* Function: calloc */
void *__cdecl calloc(size_t _Count, size_t _Size)

{
  void *pvVar1;

  /* WARNING: Could not recover jumptable at 0x00402cb0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pvVar1 = calloc(_Count, _Size);
  return pvVar1;
}

/* Function: abort */
void __cdecl abort(void)

{
  /* WARNING: Could not recover jumptable at 0x00402cb8. Too many branches */
  /* WARNING: Subroutine does not return */
  /* WARNING: Treating indirect jump as call */
  abort();
  return;
}

/* Function: _onexit */
_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;

  /* WARNING: Could not recover jumptable at 0x00402cc0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  p_Var1 = _onexit(_Func);
  return p_Var1;
}

/* Function: _initterm */
void _initterm(void)

{
  /* WARNING: Could not recover jumptable at 0x00402cc8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  _initterm();
  return;
}

/* Function: _cexit */
void __cdecl _cexit(void)

{
  /* WARNING: Could not recover jumptable at 0x00402cd0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  _cexit();
  return;
}

/* Function: _amsg_exit */
void __cdecl _amsg_exit(int param_1)

{
  /* WARNING: Could not recover jumptable at 0x00402cd8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  _amsg_exit(param_1);
  return;
}

/* Function: __setusermatherr */
void __setusermatherr(void)

{
  /* WARNING: Could not recover jumptable at 0x00402ce0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  __setusermatherr();
  return;
}

/* Function: __set_app_type */
void __cdecl __set_app_type(int param_1)

{
  /* WARNING: Could not recover jumptable at 0x00402ce8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  __set_app_type(param_1);
  return;
}

/* Function: __getmainargs */
void __getmainargs(void)

{
  /* WARNING: Could not recover jumptable at 0x00402cf8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  __getmainargs();
  return;
}

/* Function: __C_specific_handler */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

EXCEPTION_DISPOSITION
__C_specific_handler(_EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, _CONTEXT *ContextRecord,
                     _DISPATCHER_CONTEXT *DispatcherContext)

{
  EXCEPTION_DISPOSITION EVar1;

  /* WARNING: Could not recover jumptable at 0x00402d00. Too many branches */
  /* WARNING: Treating indirect jump as call */
  EVar1 = __C_specific_handler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
  return EVar1;
}

/* Function: __acrt_iob_func */
/* WARNING: Unknown calling convention */

FILE *__acrt_iob_func(uint index)

{
  FILE *pFVar1;

  pFVar1 = __iob_func();
  return (FILE *)(pFVar1 + index);
}

/* Function: mingw_get_invalid_parameter_handler */
_invalid_parameter_handler __cdecl mingw_get_invalid_parameter_handler(void)

{
  return (_invalid_parameter_handler)handler;
}

/* Function: mingw_set_invalid_parameter_handler */
_invalid_parameter_handler __cdecl mingw_set_invalid_parameter_handler(_invalid_parameter_handler _Handler)

{
  _invalid_parameter_handler p_Var1;

  p_Var1 = handler;
  LOCK();
  handler = (_invalid_parameter_handler)_Handler;
  UNLOCK();
  return (_invalid_parameter_handler)p_Var1;
}

/* Function: __p__acmdln */
/* WARNING: Unknown calling convention */

char **__p__acmdln(void)

{
  return *(char ***)_refptr___imp__acmdln;
}

/* Function: __p__fmode */
/* WARNING: Unknown calling convention */

int *__p__fmode(void)

{
  return *(int **)_refptr___imp__fmode;
}

/* Function: __iob_func */
FILE *__cdecl __iob_func(void)

{
  FILE *pFVar1;

  /* WARNING: Could not recover jumptable at 0x00402d70. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pFVar1 = __iob_func();
  return pFVar1;
}

/* Function: VirtualQuery */
SIZE_T __stdcall VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)

{
  SIZE_T SVar1;

  /* WARNING: Could not recover jumptable at 0x00402d80. Too many branches */
  /* WARNING: Treating indirect jump as call */
  SVar1 = VirtualQuery(lpAddress, lpBuffer, dwLength);
  return SVar1;
}

/* Function: VirtualProtect */
BOOL __stdcall VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)

{
  BOOL BVar1;

  /* WARNING: Could not recover jumptable at 0x00402d88. Too many branches */
  /* WARNING: Treating indirect jump as call */
  BVar1 = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
  return BVar1;
}

/* Function: UnhandledExceptionFilter */
LONG __stdcall UnhandledExceptionFilter(_EXCEPTION_POINTERS *ExceptionInfo)

{
  LONG LVar1;

  /* WARNING: Could not recover jumptable at 0x00402d90. Too many branches */
  /* WARNING: Treating indirect jump as call */
  LVar1 = UnhandledExceptionFilter(ExceptionInfo);
  return LVar1;
}

/* Function: TlsGetValue */
LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)

{
  LPVOID pvVar1;

  /* WARNING: Could not recover jumptable at 0x00402d98. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pvVar1 = TlsGetValue(dwTlsIndex);
  return pvVar1;
}

/* Function: TerminateProcess */
BOOL __stdcall TerminateProcess(HANDLE hProcess, UINT uExitCode)

{
  BOOL BVar1;

  /* WARNING: Could not recover jumptable at 0x00402da0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  BVar1 = TerminateProcess(hProcess, uExitCode);
  return BVar1;
}

/* Function: Sleep */
void __stdcall Sleep(DWORD dwMilliseconds)

{
  /* WARNING: Could not recover jumptable at 0x00402da8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  Sleep(dwMilliseconds);
  return;
}

/* Function: SetUnhandledExceptionFilter */
LPTOP_LEVEL_EXCEPTION_FILTER __stdcall SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)

{
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar1;

  /* WARNING: Could not recover jumptable at 0x00402db0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pPVar1 = SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
  return pPVar1;
}

/* Function: RtlVirtualUnwind */
PEXCEPTION_ROUTINE __stdcall RtlVirtualUnwind(DWORD HandlerType, DWORD64 ImageBase, DWORD64 ControlPc,
                                              PRUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord, PVOID *HandlerData,
                                              PDWORD64 EstablisherFrame, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)

{
  PEXCEPTION_ROUTINE puVar1;

  /* WARNING: Could not recover jumptable at 0x00402db8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  puVar1 = RtlVirtualUnwind(HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord, HandlerData,
                            EstablisherFrame, ContextPointers);
  return puVar1;
}

/* Function: RtlLookupFunctionEntry */
PRUNTIME_FUNCTION __stdcall RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable)

{
  PRUNTIME_FUNCTION p_Var1;

  /* WARNING: Could not recover jumptable at 0x00402dc0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  p_Var1 = RtlLookupFunctionEntry(ControlPc, ImageBase, HistoryTable);
  return p_Var1;
}

/* Function: RtlAddFunctionTable */
BOOLEAN __cdecl RtlAddFunctionTable(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress)

{
  BOOLEAN BVar1;

  /* WARNING: Could not recover jumptable at 0x00402dd0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  BVar1 = RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress);
  return BVar1;
}

/* Function: QueryPerformanceCounter */
BOOL __stdcall QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)

{
  BOOL BVar1;

  /* WARNING: Could not recover jumptable at 0x00402dd8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  BVar1 = QueryPerformanceCounter(lpPerformanceCount);
  return BVar1;
}

/* Function: LeaveCriticalSection */
void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
  /* WARNING: Could not recover jumptable at 0x00402de0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection(lpCriticalSection);
  return;
}

/* Function: InitializeCriticalSection */
void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
  /* WARNING: Could not recover jumptable at 0x00402de8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  InitializeCriticalSection(lpCriticalSection);
  return;
}

/* Function: GetTickCount */
DWORD __stdcall GetTickCount(void)

{
  DWORD DVar1;

  /* WARNING: Could not recover jumptable at 0x00402df0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  DVar1 = GetTickCount();
  return DVar1;
}

/* Function: GetSystemTimeAsFileTime */
void __stdcall GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)

{
  /* WARNING: Could not recover jumptable at 0x00402df8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
  return;
}

/* Function: GetStartupInfoA */
void __stdcall GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo)

{
  /* WARNING: Could not recover jumptable at 0x00402e00. Too many branches */
  /* WARNING: Treating indirect jump as call */
  GetStartupInfoA(lpStartupInfo);
  return;
}

/* Function: GetLastError */
DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;

  /* WARNING: Could not recover jumptable at 0x00402e08. Too many branches */
  /* WARNING: Treating indirect jump as call */
  DVar1 = GetLastError();
  return DVar1;
}

/* Function: GetCurrentThreadId */
DWORD __stdcall GetCurrentThreadId(void)

{
  DWORD DVar1;

  /* WARNING: Could not recover jumptable at 0x00402e10. Too many branches */
  /* WARNING: Treating indirect jump as call */
  DVar1 = GetCurrentThreadId();
  return DVar1;
}

/* Function: GetCurrentProcessId */
DWORD __stdcall GetCurrentProcessId(void)

{
  DWORD DVar1;

  /* WARNING: Could not recover jumptable at 0x00402e18. Too many branches */
  /* WARNING: Treating indirect jump as call */
  DVar1 = GetCurrentProcessId();
  return DVar1;
}

/* Function: GetCurrentProcess */
HANDLE __stdcall GetCurrentProcess(void)

{
  HANDLE pvVar1;

  /* WARNING: Could not recover jumptable at 0x00402e20. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pvVar1 = GetCurrentProcess();
  return pvVar1;
}

/* Function: EnterCriticalSection */
void __stdcall EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
  /* WARNING: Could not recover jumptable at 0x00402e28. Too many branches */
  /* WARNING: Treating indirect jump as call */
  EnterCriticalSection(lpCriticalSection);
  return;
}

/* Function: DeleteCriticalSection */
void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
  /* WARNING: Could not recover jumptable at 0x00402e30. Too many branches */
  /* WARNING: Treating indirect jump as call */
  DeleteCriticalSection(lpCriticalSection);
  return;
}

;