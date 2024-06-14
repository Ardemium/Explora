/**
 *  Generator: vscode-decompiler@0.1.0 (https://marketplace.visualstudio.com/items?itemName=tintinweb.vscode-decompiler)
 *  Target:    c:\Users\Arthu\Dev\Python\toolkit\modern3.exe
 **/

/* Function: FUN_00401180 */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulonglong FUN_00401180(undefined8 param_1, undefined *param_2, undefined8 param_3)

{
  int iVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  undefined *puVar5;
  undefined *puVar6;
  undefined *puVar7;
  longlong lVar8;
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar9;
  char **ppcVar10;
  char *pcVar11;
  undefined8 *puVar12;
  size_t sVar13;
  void *_Dst;
  undefined8 *puVar14;
  ulonglong uVar15;
  longlong lVar16;
  LPSTARTUPINFOA p_Var17;
  LPSTARTUPINFOA p_Var18;
  undefined *puVar19;
  PDWORD pDVar20;
  longlong unaff_GS_OFFSET;
  bool bVar21;
  undefined local_a8[64];
  ushort local_68;

  puVar7 = PTR_DAT_004044d0;
  p_Var18 = (LPSTARTUPINFOA)local_a8;
  p_Var17 = p_Var18;
  for (lVar16 = 0xd; lVar16 != 0; lVar16 = lVar16 + -1)
  {
    *(undefined8 *)p_Var17 = 0;
    p_Var17 = (LPSTARTUPINFOA)&p_Var17->lpReserved;
  }
  pDVar20 = (PDWORD)(ulonglong) * (uint *)PTR_DAT_004044d0;
  p_Var17 = (LPSTARTUPINFOA)0x0;
  if (*(uint *)PTR_DAT_004044d0 != 0)
  {
    GetStartupInfoA(p_Var18);
    p_Var17 = p_Var18;
  }
  puVar5 = PTR_DAT_00404420;
  lVar16 = *(longlong *)(*(longlong *)(unaff_GS_OFFSET + 0x30) + 8);
  while (true)
  {
    LOCK();
    lVar8 = *(longlong *)puVar5;
    if (lVar8 == 0)
    {
      *(longlong *)puVar5 = lVar16;
      lVar8 = 0;
    }
    puVar19 = PTR_DAT_00404470;
    p_Var18 = (LPSTARTUPINFOA)PTR_DAT_00404460;
    puVar6 = PTR_DAT_00404430;
    UNLOCK();
    if (lVar8 == 0)
    {
      bVar21 = false;
      iVar4 = *(int *)PTR_DAT_00404430;
      goto joined_r0x00401411;
    }
    if (lVar16 == lVar8)
      break;
    p_Var17 = (LPSTARTUPINFOA)0x3e8;
    Sleep(1000);
  }
  bVar21 = true;
  iVar4 = *(int *)PTR_DAT_00404430;
joined_r0x00401411:
  if (iVar4 == 1)
  {
    p_Var18 = (LPSTARTUPINFOA)0x1f;
    _amsg_exit(0x1f);
    iVar4 = *(int *)puVar6;
    p_Var17 = (LPSTARTUPINFOA)PTR_DAT_00404440;
    puVar19 = PTR_DAT_00404450;
  }
  else
  {
    if (*(int *)PTR_DAT_00404430 == 0)
    {
      *(undefined4 *)PTR_DAT_00404430 = 1;
      _initterm();
    }
    else
    {
      DAT_00407008 = 1;
      p_Var18 = p_Var17;
      puVar19 = param_2;
    }
    iVar4 = *(int *)puVar6;
    param_2 = puVar19;
    p_Var17 = (LPSTARTUPINFOA)PTR_DAT_00404440;
    puVar19 = PTR_DAT_00404450;
  }
  PTR_DAT_00404440 = (undefined *)p_Var17;
  PTR_DAT_00404450 = puVar19;
  if (iVar4 == 1)
  {
    _initterm();
    *(undefined4 *)puVar6 = 2;
    p_Var18 = p_Var17;
    param_2 = puVar19;
  }
  if (!bVar21)
  {
    LOCK();
    *(undefined8 *)puVar5 = 0;
    UNLOCK();
  }
  if (*(code **)PTR_PTR_tls_callback_0_004043c0 != (code *)0x0)
  {
    param_2 = (undefined *)0x2;
    p_Var18 = (LPSTARTUPINFOA)0x0;
    (**(code **)PTR_PTR_tls_callback_0_004043c0)(0, 2, 0);
  }
  FUN_00401dc0(p_Var18, param_2, param_3, pDVar20);
  pPVar9 = SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)&LAB_004023d0);
  *(LPTOP_LEVEL_EXCEPTION_FILTER *)PTR_DAT_00404410 = pPVar9;
  FUN_004022d0();
  FUN_00402d00(&LAB_00401000);
  FUN_00401b30();
  _DAT_00407968 = PTR_IMAGE_DOS_HEADER_004043d0;
  ppcVar10 = (char **)FUN_00402d10();
  iVar4 = DAT_00407028;
  bVar21 = false;
  pcVar11 = *ppcVar10;
  if (pcVar11 != (char *)0x0)
  {
    do
    {
      cVar3 = *pcVar11;
      if (cVar3 < '!')
      {
        _DAT_00407960 = pcVar11;
        if (cVar3 == '\0')
          break;
        if (!bVar21)
          goto LAB_004012d0;
        bVar21 = true;
      }
      else if (cVar3 == '\"')
      {
        bVar21 = (bool)(bVar21 ^ 1);
      }
      pcVar11 = pcVar11 + 1;
    } while (true);
  }
  goto LAB_004012f0;
LAB_004012d0:
  if (cVar3 != '\0')
  {
    do
    {
      pcVar2 = pcVar11 + 1;
      pcVar11 = pcVar11 + 1;
      _DAT_00407960 = pcVar11;
      if (*pcVar2 == '\0')
        break;
    } while (*pcVar2 < '!');
  }
LAB_004012f0:
  if ((*(int *)puVar7 != 0) && (_DAT_00403000 = 10, (local_a8[60] & 1) != 0))
  {
    _DAT_00403000 = (uint)local_68;
  }
  iVar1 = DAT_00407028 + 1;
  puVar12 = (undefined8 *)malloc((longlong)iVar1 * 8);
  lVar16 = (longlong)DAT_00407020;
  puVar14 = puVar12;
  if (0 < iVar4)
  {
    uVar15 = 0;
    do
    {
      sVar13 = strlen(*(char **)(lVar16 + uVar15 * 8));
      _Dst = malloc(sVar13 + 1);
      puVar12[uVar15] = _Dst;
      memcpy(_Dst, *(void **)(lVar16 + uVar15 * 8), sVar13 + 1);
      bVar21 = iVar4 - 1 != uVar15;
      uVar15 = uVar15 + 1;
    } while (bVar21);
    puVar14 = puVar12 + (longlong)iVar1 + -1;
  }
  *puVar14 = 0;
  DAT_00407020 = puVar12;
  FUN_00401740();
  **(undefined8 **)PTR_PTR___initenv_004043e0 = DAT_00407018;
  uVar15 = FUN_00401642();
  DAT_00407010 = (uint)uVar15;
  if (DAT_0040700c == 0)
  {
    /* WARNING: Subroutine does not return */
    exit(DAT_00407010);
  }
  if (DAT_00407008 == 0)
  {
    _cexit();
    return (ulonglong)DAT_00407010;
  }
  return uVar15;
}

/* Function: entry */
void entry(undefined8 param_1, undefined *param_2, undefined8 param_3)

{
  *(undefined4 *)PTR_DAT_004044d0 = 0;
  FUN_00401780();
  FUN_00401180(param_1, param_2, param_3);
  return;
}

/* Function: FUN_00401520 */
int FUN_00401520(_onexit_t param_1)

{
  _onexit_t p_Var1;

  p_Var1 = _onexit(param_1);
  return -(uint)(p_Var1 == (_onexit_t)0x0);
}

/* Function: FUN_00401560 */
undefined8 FUN_00401560(void)

{
  char local_58[72];
  FILE *local_10;

  local_10 = fopen("flag.txt", "r");
  if (local_10 == (FILE *)0x0)
  {
    puts("Something is wrong, please contact an admin!");
    /* WARNING: Subroutine does not return */
    exit(2);
  }
  fgets(local_58, 0x3c, local_10);
  puts(local_58);
  return 0;
}

/* Function: FUN_004015cb */
undefined8 FUN_004015cb(char *param_1)

{
  char *local_res8;
  char acStack_38[40];
  int local_10;
  uint local_c;

  local_10 = 0x28;
  local_res8 = param_1;
  for (local_c = 0; (*local_res8 != '\0' && (local_c < 0x28)); local_c = local_c + 1)
  {
    acStack_38[(int)local_c] = *local_res8;
    if (*local_res8 == 'z')
    {
      local_c = local_c + 1;
      acStack_38[(int)local_c] = -0x77;
    }
    local_res8 = local_res8 + 1;
  }
  if (local_10 != 0x28)
  {
    FUN_00401560();
  }
  return 0;
}

/* Function: FUN_00401642 */
undefined8 FUN_00401642(void)

{
  char local_38[48];

  FUN_00401740();
  puts("What\'s your name ?");
  _read(0, local_38, 0x28);
  FUN_004015cb(local_38);
  return 0;
}

/* Function: FUN_00401690 */
void FUN_00401690(void)

{
  code *pcVar1;

  pcVar1 = *(code **)PTR_DAT_00403010;
  while (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    pcVar1 = *(code **)(PTR_DAT_00403010 + 8);
    PTR_DAT_00403010 = PTR_DAT_00403010 + 8;
  }
  return;
}

/* Function: FUN_004016d0 */
void FUN_004016d0(void)

{
  code **ppcVar1;
  uint uVar2;
  ulonglong uVar3;
  code **ppcVar4;

  uVar2 = (uint) * (undefined8 *)PTR_DAT_00404390;
  if (uVar2 == 0xffffffff)
  {
    uVar3 = 0;
    do
    {
      uVar2 = (uint)uVar3;
      uVar3 = (ulonglong)(uVar2 + 1);
    } while (*(longlong *)(PTR_DAT_00404390 + uVar3 * 8) != 0);
  }
  if (uVar2 != 0)
  {
    ppcVar4 = (code **)(PTR_DAT_00404390 + (ulonglong)uVar2 * 8);
    ppcVar1 = (code **)(PTR_DAT_00404390 + ((ulonglong)uVar2 - (ulonglong)(uVar2 - 1)) * 8 + -8);
    do
    {
      (**ppcVar4)();
      ppcVar4 = ppcVar4 + -1;
    } while (ppcVar4 != ppcVar1);
  }
  FUN_00401520(FUN_00401690);
  return;
}

/* Function: FUN_00401740 */
void FUN_00401740(void)

{
  if (DAT_00407030 != 0)
  {
    return;
  }
  DAT_00407030 = 1;
  FUN_004016d0();
  return;
}

/* Function: FUN_00401770 */
undefined8 FUN_00401770(void)

{
  return 0;
}

/* Function: FUN_00401780 */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00401780(void)

{
  _FILETIME _Var1;
  DWORD DVar2;
  DWORD DVar3;
  DWORD DVar4;
  _FILETIME local_38;
  LARGE_INTEGER local_30;

  local_38.dwLowDateTime = 0;
  local_38.dwHighDateTime = 0;
  if (DAT_004030a0 != 0x2b992ddfa232)
  {
    _DAT_004030b0 = ~DAT_004030a0;
    return;
  }
  GetSystemTimeAsFileTime(&local_38);
  _Var1 = local_38;
  DVar2 = GetCurrentProcessId();
  DVar3 = GetCurrentThreadId();
  DVar4 = GetTickCount();
  QueryPerformanceCounter(&local_30);
  DAT_004030a0 = ((ulonglong)DVar4 ^
                  (ulonglong)DVar3 ^ (ulonglong)DVar2 ^ (ulonglong)_Var1 ^ local_30.QuadPart) &
                 0xffffffffffff;
  if (DAT_004030a0 == 0x2b992ddfa232)
  {
    _DAT_004030b0 = 0xffffd466d2205dcc;
    DAT_004030a0 = 0x2b992ddfa233;
  }
  else
  {
    _DAT_004030b0 = ~DAT_004030a0;
  }
  return;
}

/* Function: tls_callback_1 */
undefined8 tls_callback_1(undefined8 param_1, uint param_2)

{
  if ((param_2 != 3) && (param_2 != 0))
  {
    return 1;
  }
  FUN_00402700(param_1, param_2);
  return 1;
}

/* Function: tls_callback_0 */
/* WARNING: Removing unreachable block (ram,0x004019d3) */
/* WARNING: Removing unreachable block (ram,0x004019d8) */
/* WARNING: Removing unreachable block (ram,0x004019e0) */
/* WARNING: Removing unreachable block (ram,0x004019e2) */
/* WARNING: Removing unreachable block (ram,0x004019eb) */

undefined8 tls_callback_0(undefined8 param_1, int param_2)

{
  if (*(int *)PTR_DAT_00404370 != 2)
  {
    *(undefined4 *)PTR_DAT_00404370 = 2;
  }
  if ((param_2 != 2) && (param_2 == 1))
  {
    FUN_00402700(param_1, 1);
    return 1;
  }
  return 1;
}

/* Function: FUN_00401b30 */
void FUN_00401b30(void)

{
  return;
}

/* Function: FUN_00401b40 */
void FUN_00401b40(char *param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4)

{
  FILE *pFVar1;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;

  local_res10 = param_2;
  local_res18 = param_3;
  local_res20 = param_4;
  pFVar1 = FUN_00402cd0(2);
  fwrite("Mingw-w64 runtime failure:\n", 1, 0x1b, pFVar1);
  pFVar1 = FUN_00402cd0(2);
  vfprintf(pFVar1, param_1, (va_list)&local_res10);
  /* WARNING: Subroutine does not return */
  abort();
}

/* Function: FUN_00401bb0 */
void FUN_00401bb0(undefined8 *param_1, undefined8 *param_2, undefined8 param_3, PDWORD param_4)

{
  int *piVar1;
  undefined8 uVar2;
  byte bVar3;
  ushort uVar4;
  LPVOID lpAddress;
  undefined *puVar5;
  undefined *puVar6;
  uint uVar7;
  BOOL BVar8;
  DWORD DVar9;
  ulonglong *puVar10;
  longlong lVar11;
  undefined4 *puVar12;
  IMAGE_DOS_HEADER *pIVar13;
  SIZE_T SVar14;
  ulonglong uVar15;
  DWORD *pDVar16;
  int iVar17;
  undefined4 uVar18;
  longlong *plVar19;
  PDWORD *ppDVar20;
  uint uVar21;
  uint *puVar22;
  int *piVar23;
  longlong lVar24;
  ulonglong in_R8;
  ulonglong uVar25;
  undefined8 in_XMM3_Qa;
  undefined8 auStack_150[5];
  undefined4 auStack_128[2];
  ulonglong auStack_120[10];
  undefined auStack_d0[8];
  undefined8 uStack_c8;
  undefined8 *puStack_b0;
  longlong lStack_a8;
  undefined8 *puStack_a0;
  _MEMORY_BASIC_INFORMATION local_58;

  lVar24 = (longlong)DAT_00407614;
  uVar25 = in_R8;
  if (DAT_00407614 < 1)
    goto LAB_00401d58;
  iVar17 = 0;
  puVar10 = (ulonglong *)((longlong)DAT_00407618 + 0x18);
  do
  {
    if (((undefined8 *)*puVar10 <= param_1) &&
        (uVar25 = (ulonglong) * (uint *)(puVar10[1] + 8),
         param_1 < (undefined8 *)((longlong)(undefined8 *)*puVar10 + uVar25)))
      goto LAB_00401c87;
    iVar17 = iVar17 + 1;
    puVar10 = puVar10 + 5;
  } while (iVar17 != DAT_00407614);
  while (lVar11 = FUN_00402910((longlong)param_1), lVar11 != 0)
  {
    lVar24 = lVar24 * 0x28;
    puVar12 = (undefined4 *)((longlong)DAT_00407618 + lVar24);
    *(longlong *)(puVar12 + 8) = lVar11;
    *puVar12 = 0;
    pIVar13 = FUN_00402a40();
    uVar21 = *(uint *)(lVar11 + 0xc);
    *(char **)((longlong)DAT_00407618 + lVar24 + 0x18) = pIVar13->e_magic + uVar21;
    SVar14 = VirtualQuery(pIVar13->e_magic + uVar21, &local_58, 0x30);
    if (SVar14 == 0)
      goto LAB_00401da1;
    if (((local_58.Protect - 0x40 & 0xffffffbf) == 0) || ((local_58.Protect - 4 & 0xfffffffb) == 0))
    {
    LAB_00401c80:
      DAT_00407614 = DAT_00407614 + 1;
    LAB_00401c87:
      uVar21 = (uint)in_R8;
      if (uVar21 < 8)
      {
        if ((in_R8 & 4) == 0)
        {
          if ((uVar21 != 0) && (*(undefined *)param_1 = *(undefined *)param_2, (in_R8 & 2) != 0))
          {
            *(undefined2 *)((longlong)param_1 + ((in_R8 & 0xffffffff) - 2)) =
                *(undefined2 *)((longlong)param_2 + ((in_R8 & 0xffffffff) - 2));
          }
        }
        else
        {
          *(undefined4 *)param_1 = *(undefined4 *)param_2;
          *(undefined4 *)((longlong)param_1 + ((in_R8 & 0xffffffff) - 4)) =
              *(undefined4 *)((longlong)param_2 + ((in_R8 & 0xffffffff) - 4));
        }
      }
      else
      {
        *param_1 = *param_2;
        *(undefined8 *)((longlong)param_1 + ((in_R8 & 0xffffffff) - 8)) =
            *(undefined8 *)((longlong)param_2 + ((in_R8 & 0xffffffff) - 8));
        lVar24 = (longlong)param_1 - ((ulonglong)(param_1 + 1) & 0xfffffffffffffff8);
        uVar21 = uVar21 + (int)lVar24 & 0xfffffff8;
        if (7 < uVar21)
        {
          uVar7 = 0;
          do
          {
            uVar25 = (ulonglong)uVar7;
            uVar7 = uVar7 + 8;
            *(undefined8 *)(((ulonglong)(param_1 + 1) & 0xfffffffffffffff8) + uVar25) =
                *(undefined8 *)((longlong)param_2 + (uVar25 - lVar24));
          } while (uVar7 < uVar21);
          return;
        }
      }
      return;
    }
    uVar25 = 0x40;
    param_4 = (PDWORD)((longlong)DAT_00407618 + lVar24);
    *(PVOID *)(param_4 + 2) = local_58.BaseAddress;
    *(SIZE_T *)(param_4 + 4) = local_58.RegionSize;
    BVar8 = VirtualProtect(local_58.BaseAddress, local_58.RegionSize, 0x40, param_4);
    if (BVar8 != 0)
      goto LAB_00401c80;
    DVar9 = GetLastError();
    FUN_00401b40("  VirtualProtect failed with code 0x%x", (ulonglong)DVar9, uVar25, param_4);
  LAB_00401d58:
    lVar24 = 0;
  }
  FUN_00401b40("Address %p has no image-section", param_1, uVar25, param_4);
LAB_00401da1:
  uVar25 = *(ulonglong *)((longlong)DAT_00407618 + lVar24 + 0x18);
  FUN_00401b40("  VirtualQuery failed for %d bytes at address %p", (ulonglong) * (uint *)(lVar11 + 8),
               uVar25, param_4);
  if (DAT_00407610 != 0)
  {
    return;
  }
  DAT_00407610 = 1;
  auStack_120[5] = 0x401e07;
  puStack_b0 = param_2;
  lStack_a8 = lVar24;
  puStack_a0 = param_1;
  FUN_004029a0();
  auStack_120[5] = 0x401e1e;
  uVar15 = FUN_00402bc0();
  puVar6 = PTR_IMAGE_DOS_HEADER_004043d0;
  puVar5 = PTR_DAT_004043a0;
  DAT_00407614 = 0;
  lVar24 = -uVar15;
  DAT_00407618 = auStack_d0 + lVar24;
  if ((longlong)PTR_DAT_004043a0 - (longlong)PTR_DAT_004043b0 < 8)
  {
    DAT_00407614 = 0;
    return;
  }
  iVar17 = *(int *)PTR_DAT_004043b0;
  piVar23 = (int *)PTR_DAT_004043b0;
  if ((longlong)PTR_DAT_004043a0 - (longlong)PTR_DAT_004043b0 < 0xc)
  {
  LAB_00401e5d:
    if (iVar17 == 0)
    {
      uVar21 = piVar23[1];
    LAB_00401e68:
      if (uVar21 == 0)
      {
        uVar15 = (ulonglong)(uint)piVar23[2];
        if (piVar23[2] != 1)
        {
        LAB_00402098:
          uVar18 = 0x4042a0;
          *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x28) = 0x4020a4;
          FUN_00401b40("  Unknown pseudo relocation protocol version %d.\n", uVar15, uVar25, param_4);
          if (DAT_00407620 != (code *)0x0)
          {
            uVar2 = *(undefined8 *)((longlong)&uStack_c8 + lVar24);
            *(undefined4 *)((longlong)auStack_128 + lVar24) = uVar18;
            *(ulonglong *)((longlong)auStack_120 + lVar24) = uVar15;
            *(undefined8 *)((longlong)auStack_120 + lVar24 + 8) = param_3;
            *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x10) = in_XMM3_Qa;
            *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x18) = uVar2;
            *(undefined8 *)((longlong)auStack_150 + lVar24) = 0x4020eb;
            (*DAT_00407620)((longlong)auStack_128 + lVar24);
          }
          return;
        }
        puVar22 = (uint *)(piVar23 + 3);
        if (PTR_DAT_004043a0 <= puVar22)
        {
          DAT_00407614 = 0;
          return;
        }
        do
        {
          while (true)
          {
            bVar3 = *(byte *)(puVar22 + 2);
            uVar15 = (ulonglong)bVar3;
            ppDVar20 = (PDWORD *)(puVar6 + *puVar22);
            plVar19 = (longlong *)(puVar6 + puVar22[1]);
            param_4 = *ppDVar20;
            if (bVar3 != 0x20)
              break;
            uVar21 = *(uint *)plVar19;
            uVar25 = (ulonglong)uVar21 | 0xffffffff00000000;
            if (-1 < (int)uVar21)
            {
              uVar25 = (ulonglong)uVar21;
            }
            uStack_c8 = (uVar25 - (longlong)ppDVar20) + (longlong)param_4;
            *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x28) = 0x40202a;
            FUN_00401bb0(plVar19, &uStack_c8, param_3, param_4);
          LAB_00401ed0:
            puVar22 = puVar22 + 3;
            if (puVar5 <= puVar22)
              goto LAB_00401f50;
          }
          if (0x20 < bVar3)
          {
            if (bVar3 == 0x40)
            {
              uStack_c8 = (*plVar19 - (longlong)ppDVar20) + (longlong)param_4;
              *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x28) = 0x401ff8;
              FUN_00401bb0(plVar19, &uStack_c8, param_3, param_4);
              goto LAB_00401ed0;
            }
          LAB_00402081:
            uStack_c8 = 0;
            *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x28) = 0x402098;
            uVar25 = uVar15;
            FUN_00401b40("  Unknown pseudo relocation bit size %d.\n", uVar15, uVar15, param_4);
            goto LAB_00402098;
          }
          if (bVar3 == 8)
          {
            bVar3 = *(byte *)plVar19;
            uVar25 = (ulonglong)bVar3;
            if ((char)bVar3 < '\0')
            {
              uVar25 = (ulonglong)bVar3 | 0xffffffffffffff00;
            }
            uStack_c8 = (uVar25 - (longlong)ppDVar20) + (longlong)param_4;
            *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x28) = 0x401ed0;
            FUN_00401bb0(plVar19, &uStack_c8, param_3, param_4);
            goto LAB_00401ed0;
          }
          if (bVar3 != 0x10)
            goto LAB_00402081;
          uVar4 = *(ushort *)plVar19;
          uVar25 = (ulonglong)uVar4;
          if ((short)uVar4 < 0)
          {
            uVar25 = (ulonglong)uVar4 | 0xffffffffffff0000;
          }
          puVar22 = puVar22 + 3;
          uStack_c8 = (uVar25 - (longlong)ppDVar20) + (longlong)param_4;
          *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x28) = 0x401f41;
          FUN_00401bb0(plVar19, &uStack_c8, param_3, param_4);
        } while (puVar22 < puVar5);
        goto LAB_00401f50;
      }
    }
  }
  else if (iVar17 == 0)
  {
    uVar21 = *(uint *)(PTR_DAT_004043b0 + 4);
    if ((uVar21 | *(uint *)(PTR_DAT_004043b0 + 8)) == 0)
    {
      iVar17 = *(int *)(PTR_DAT_004043b0 + 0xc);
      piVar23 = (int *)(PTR_DAT_004043b0 + 0xc);
      goto LAB_00401e5d;
    }
    goto LAB_00401e68;
  }
  if (PTR_DAT_004043a0 <= piVar23)
  {
    DAT_00407614 = 0;
    return;
  }
  piVar1 = (int *)((longlong)piVar23 +
                   ((ulonglong)(PTR_DAT_004043a0 + (-1 - (longlong)piVar23)) & 0xfffffffffffffff8) +
                   8);
  do
  {
    uVar21 = piVar23[1];
    iVar17 = *piVar23;
    piVar23 = piVar23 + 2;
    uStack_c8 = CONCAT44(uStack_c8._4_4_, iVar17 + *(int *)(puVar6 + uVar21));
    *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x28) = 0x402077;
    FUN_00401bb0((undefined8 *)(puVar6 + uVar21), &uStack_c8, param_3, param_4);
  } while (piVar23 != piVar1);
LAB_00401f50:
  if (0 < DAT_00407614)
  {
    lVar11 = 0;
    iVar17 = 0;
    do
    {
      pDVar16 = (DWORD *)(DAT_00407618 + lVar11);
      DVar9 = *pDVar16;
      if (DVar9 != 0)
      {
        SVar14 = *(SIZE_T *)(pDVar16 + 4);
        lpAddress = *(LPVOID *)(pDVar16 + 2);
        *(undefined8 *)((longlong)auStack_120 + lVar24 + 0x28) = 0x401f90;
        VirtualProtect(lpAddress, SVar14, DVar9, (PDWORD)&uStack_c8);
      }
      iVar17 = iVar17 + 1;
      lVar11 = lVar11 + 0x28;
    } while (iVar17 < DAT_00407614);
  }
  return;
}

/* Function: FUN_00401dc0 */
void FUN_00401dc0(undefined8 param_1, undefined8 param_2, undefined8 param_3, PDWORD param_4)

{
  int *piVar1;
  undefined8 uVar2;
  byte bVar3;
  ushort uVar4;
  DWORD flNewProtect;
  SIZE_T dwSize;
  LPVOID lpAddress;
  longlong lVar5;
  undefined *puVar6;
  undefined *puVar7;
  uint uVar8;
  ulonglong uVar9;
  DWORD *pDVar10;
  undefined4 uVar11;
  longlong *plVar12;
  PDWORD *ppDVar13;
  uint *puVar14;
  longlong lVar15;
  int *piVar16;
  int iVar17;
  ulonglong in_R8;
  undefined8 in_XMM3_Qa;
  undefined8 auStack_d8[5];
  undefined4 auStack_b0[2];
  ulonglong auStack_a8[10];
  undefined auStack_58[8];
  undefined8 local_50;

  if (DAT_00407610 != 0)
  {
    return;
  }
  DAT_00407610 = 1;
  auStack_a8[5] = 0x401e07;
  FUN_004029a0();
  auStack_a8[5] = 0x401e1e;
  uVar9 = FUN_00402bc0();
  puVar7 = PTR_IMAGE_DOS_HEADER_004043d0;
  puVar6 = PTR_DAT_004043a0;
  DAT_00407614 = 0;
  lVar5 = -uVar9;
  DAT_00407618 = auStack_58 + lVar5;
  if ((longlong)PTR_DAT_004043a0 - (longlong)PTR_DAT_004043b0 < 8)
  {
    DAT_00407614 = 0;
    return;
  }
  iVar17 = *(int *)PTR_DAT_004043b0;
  piVar16 = (int *)PTR_DAT_004043b0;
  if ((longlong)PTR_DAT_004043a0 - (longlong)PTR_DAT_004043b0 < 0xc)
  {
  LAB_00401e5d:
    if (iVar17 == 0)
    {
      uVar8 = piVar16[1];
    LAB_00401e68:
      if (uVar8 == 0)
      {
        uVar9 = (ulonglong)(uint)piVar16[2];
        if (piVar16[2] != 1)
        {
        LAB_00402098:
          uVar11 = 0x4042a0;
          *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x28) = 0x4020a4;
          FUN_00401b40("  Unknown pseudo relocation protocol version %d.\n", uVar9, in_R8, param_4);
          if (DAT_00407620 != (code *)0x0)
          {
            uVar2 = *(undefined8 *)((longlong)&local_50 + lVar5);
            *(undefined4 *)((longlong)auStack_b0 + lVar5) = uVar11;
            *(ulonglong *)((longlong)auStack_a8 + lVar5) = uVar9;
            *(undefined8 *)((longlong)auStack_a8 + lVar5 + 8) = param_3;
            *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x10) = in_XMM3_Qa;
            *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x18) = uVar2;
            *(undefined8 *)((longlong)auStack_d8 + lVar5) = 0x4020eb;
            (*DAT_00407620)((longlong)auStack_b0 + lVar5);
          }
          return;
        }
        puVar14 = (uint *)(piVar16 + 3);
        if (PTR_DAT_004043a0 <= puVar14)
        {
          DAT_00407614 = 0;
          return;
        }
        do
        {
          while (true)
          {
            bVar3 = *(byte *)(puVar14 + 2);
            uVar9 = (ulonglong)bVar3;
            ppDVar13 = (PDWORD *)(puVar7 + *puVar14);
            plVar12 = (longlong *)(puVar7 + puVar14[1]);
            param_4 = *ppDVar13;
            if (bVar3 != 0x20)
              break;
            uVar8 = *(uint *)plVar12;
            uVar9 = (ulonglong)uVar8 | 0xffffffff00000000;
            if (-1 < (int)uVar8)
            {
              uVar9 = (ulonglong)uVar8;
            }
            local_50 = (uVar9 - (longlong)ppDVar13) + (longlong)param_4;
            *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x28) = 0x40202a;
            FUN_00401bb0(plVar12, &local_50, param_3, param_4);
          LAB_00401ed0:
            puVar14 = puVar14 + 3;
            if (puVar6 <= puVar14)
              goto LAB_00401f50;
          }
          if (0x20 < bVar3)
          {
            if (bVar3 == 0x40)
            {
              local_50 = (*plVar12 - (longlong)ppDVar13) + (longlong)param_4;
              *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x28) = 0x401ff8;
              FUN_00401bb0(plVar12, &local_50, param_3, param_4);
              goto LAB_00401ed0;
            }
          LAB_00402081:
            local_50 = 0;
            *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x28) = 0x402098;
            in_R8 = uVar9;
            FUN_00401b40("  Unknown pseudo relocation bit size %d.\n", uVar9, uVar9, param_4);
            goto LAB_00402098;
          }
          if (bVar3 == 8)
          {
            bVar3 = *(byte *)plVar12;
            uVar9 = (ulonglong)bVar3;
            if ((char)bVar3 < '\0')
            {
              uVar9 = (ulonglong)bVar3 | 0xffffffffffffff00;
            }
            local_50 = (uVar9 - (longlong)ppDVar13) + (longlong)param_4;
            *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x28) = 0x401ed0;
            FUN_00401bb0(plVar12, &local_50, param_3, param_4);
            goto LAB_00401ed0;
          }
          if (bVar3 != 0x10)
            goto LAB_00402081;
          uVar4 = *(ushort *)plVar12;
          uVar9 = (ulonglong)uVar4;
          if ((short)uVar4 < 0)
          {
            uVar9 = (ulonglong)uVar4 | 0xffffffffffff0000;
          }
          puVar14 = puVar14 + 3;
          local_50 = (uVar9 - (longlong)ppDVar13) + (longlong)param_4;
          *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x28) = 0x401f41;
          FUN_00401bb0(plVar12, &local_50, param_3, param_4);
        } while (puVar14 < puVar6);
        goto LAB_00401f50;
      }
    }
  }
  else if (iVar17 == 0)
  {
    uVar8 = *(uint *)(PTR_DAT_004043b0 + 4);
    if ((uVar8 | *(uint *)(PTR_DAT_004043b0 + 8)) == 0)
    {
      iVar17 = *(int *)(PTR_DAT_004043b0 + 0xc);
      piVar16 = (int *)(PTR_DAT_004043b0 + 0xc);
      goto LAB_00401e5d;
    }
    goto LAB_00401e68;
  }
  if (PTR_DAT_004043a0 <= piVar16)
  {
    DAT_00407614 = 0;
    return;
  }
  piVar1 = (int *)((longlong)piVar16 +
                   ((ulonglong)(PTR_DAT_004043a0 + (-1 - (longlong)piVar16)) & 0xfffffffffffffff8) +
                   8);
  do
  {
    uVar8 = piVar16[1];
    iVar17 = *piVar16;
    piVar16 = piVar16 + 2;
    local_50 = CONCAT44(local_50._4_4_, iVar17 + *(int *)(puVar7 + uVar8));
    *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x28) = 0x402077;
    FUN_00401bb0((undefined8 *)(puVar7 + uVar8), &local_50, param_3, param_4);
  } while (piVar16 != piVar1);
LAB_00401f50:
  if (0 < DAT_00407614)
  {
    lVar15 = 0;
    iVar17 = 0;
    do
    {
      pDVar10 = (DWORD *)(DAT_00407618 + lVar15);
      flNewProtect = *pDVar10;
      if (flNewProtect != 0)
      {
        dwSize = *(SIZE_T *)(pDVar10 + 4);
        lpAddress = *(LPVOID *)(pDVar10 + 2);
        *(undefined8 *)((longlong)auStack_a8 + lVar5 + 0x28) = 0x401f90;
        VirtualProtect(lpAddress, dwSize, flNewProtect, (PDWORD)&local_50);
      }
      iVar17 = iVar17 + 1;
      lVar15 = lVar15 + 0x28;
    } while (iVar17 < DAT_00407614);
  }
  return;
}

/* Function: FUN_00402100 */
void FUN_00402100(undefined8 param_1)

{
  DAT_00407620 = param_1;
  __setusermatherr();
  return;
}

/* Function: FUN_00402110 */
bool FUN_00402110(uint *param_1)

{
  uint uVar1;
  code *extraout_RAX;
  code *extraout_RAX_00;
  code *extraout_RAX_01;
  code *pcVar2;
  code *extraout_RAX_02;

  uVar1 = *param_1;
  if (0xc0000096 < uVar1)
  {
    return true;
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
        goto LAB_004021fd;
      signal(8);
      FUN_00401b30();
    default:
      return false;
    case 0xc0000094:
      signal(8);
      pcVar2 = extraout_RAX_01;
      if (extraout_RAX_01 == (code *)0x1)
      {
        signal(8);
        return false;
      }
    LAB_004021fd:
      if (pcVar2 != (code *)0x0)
      {
        (*pcVar2)(8);
        return false;
      }
      return true;
    case 0xc0000096:
      goto switchD_00402140_caseD_c0000096;
    }
  }
  if (uVar1 == 0xc0000005)
  {
    signal(0xb);
    if (extraout_RAX_02 == (code *)0x1)
    {
      signal(0xb);
      return false;
    }
    if (extraout_RAX_02 != (code *)0x0)
    {
      (*extraout_RAX_02)(0xb);
      return false;
    }
  }
  else
  {
    if (uVar1 < 0xc0000006)
    {
      return uVar1 != 0x80000002;
    }
    if (uVar1 == 0xc0000008)
    {
      return false;
    }
    if (uVar1 != 0xc000001d)
    {
      return true;
    }
  switchD_00402140_caseD_c0000096:
    signal(4);
    if (extraout_RAX_00 == (code *)0x1)
    {
      signal(4);
      return false;
    }
    if (extraout_RAX_00 != (code *)0x0)
    {
      (*extraout_RAX_00)(4);
      return false;
    }
  }
  return true;
}

/* Function: FUN_004022d0 */
int FUN_004022d0(void)

{
  int iVar1;
  IMAGE_DOS_HEADER *BaseAddress;
  char *pcVar2;
  longlong lVar3;
  DWORD EntryCount;
  int *piVar4;
  undefined8 *puVar5;
  undefined1 *puVar6;
  longlong lVar7;

  BaseAddress = FUN_00402a40();
  iVar1 = DAT_00407648;
  if ((DAT_00407648 == 0) && (BaseAddress != (IMAGE_DOS_HEADER *)0x0))
  {
    DAT_00407648 = 1;
    pcVar2 = FUN_00402870(".pdata");
    if (pcVar2 == (char *)0x0)
    {
      lVar7 = 0;
      puVar5 = (undefined8 *)&DAT_00407760;
      for (lVar3 = 0x30; lVar3 != 0; lVar3 = lVar3 + -1)
      {
        *puVar5 = 0;
        puVar5 = puVar5 + 1;
      }
      puVar5 = (undefined8 *)&DAT_00407660;
      for (lVar3 = 0x20; lVar3 != 0; lVar3 = lVar3 + -1)
      {
        *puVar5 = 0;
        puVar5 = puVar5 + 1;
      }
      piVar4 = &DAT_00407760;
      puVar6 = &DAT_00407660;
      do
      {
        lVar3 = FUN_004029d0(lVar7);
        if (lVar3 == 0)
        {
          if (lVar7 == 0)
            goto LAB_0040230c;
          EntryCount = (DWORD)lVar7;
          goto LAB_004023b5;
        }
        *puVar6 = 9;
        lVar7 = lVar7 + 1;
        *(int *)(puVar6 + 4) = 0x402110 - (int)BaseAddress;
        iVar1 = *(int *)(lVar3 + 0xc);
        *piVar4 = iVar1;
        piVar4[1] = iVar1 + *(int *)(lVar3 + 8);
        piVar4[2] = (int)puVar6 - (int)BaseAddress;
        piVar4 = piVar4 + 3;
        puVar6 = puVar6 + 8;
      } while (lVar7 != 0x20);
      EntryCount = 0x20;
    LAB_004023b5:
      RtlAddFunctionTable((PRUNTIME_FUNCTION)&DAT_00407760, EntryCount, (DWORD64)BaseAddress);
    }
  LAB_0040230c:
    iVar1 = 1;
  }
  return iVar1;
}

/* Function: FUN_00402580 */
void FUN_00402580(void)

{
  DWORD *pDVar1;
  DWORD DVar2;
  LPVOID pvVar3;

  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00407900);
  for (pDVar1 = DAT_004078e0; pDVar1 != (DWORD *)0x0; pDVar1 = *(DWORD **)(pDVar1 + 4))
  {
    pvVar3 = TlsGetValue(*pDVar1);
    DVar2 = GetLastError();
    if ((DVar2 == 0) && (pvVar3 != (LPVOID)0x0))
    {
      (**(code **)(pDVar1 + 2))(pvVar3);
    }
  }
  /* WARNING: Could not recover jumptable at 0x004025e4. Too many branches */
  /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00407900);
  return;
}

/* Function: FUN_00402700 */
undefined8 FUN_00402700(undefined8 param_1, uint param_2)

{
  void *pvVar1;
  void *_Memory;

  if (param_2 != 2)
  {
    if (param_2 < 3)
    {
      if (param_2 == 0)
      {
        if (DAT_004078e8 != 0)
        {
          FUN_00402580();
        }
        if (DAT_004078e8 == 1)
        {
          DAT_004078e8 = 1;
          _Memory = DAT_004078e0;
          while (_Memory != (void *)0x0)
          {
            pvVar1 = *(void **)((longlong)_Memory + 0x10);
            free(_Memory);
            _Memory = pvVar1;
          }
          DAT_004078e0 = (void *)0x0;
          DAT_004078e8 = 0;
          DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_00407900);
        }
      }
      else
      {
        if (DAT_004078e8 == 0)
        {
          InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_00407900);
        }
        DAT_004078e8 = 1;
      }
    }
    else if ((param_2 == 3) && (DAT_004078e8 != 0))
    {
      FUN_00402580();
    }
    return 1;
  }
  FUN_00401b30();
  return 1;
}

/* Function: FUN_004027e0 */
bool FUN_004027e0(longlong param_1)

{
  int *piVar1;
  bool bVar2;

  piVar1 = (int *)(*(int *)(param_1 + 0x3c) + param_1);
  bVar2 = false;
  if (*piVar1 == 0x4550)
  {
    bVar2 = *(short *)(piVar1 + 6) == 0x20b;
  }
  return bVar2;
}

/* Function: FUN_00402870 */
char *FUN_00402870(char *param_1)

{
  char *pcVar1;
  bool bVar2;
  int iVar3;
  size_t sVar4;
  undefined7 extraout_var;
  undefined *puVar5;
  char *_Str1;

  sVar4 = strlen(param_1);
  if (8 < sVar4)
  {
    return (char *)0x0;
  }
  if ((*(short *)PTR_IMAGE_DOS_HEADER_004043d0 == 0x5a4d) &&
      (puVar5 = PTR_IMAGE_DOS_HEADER_004043d0,
       bVar2 = FUN_004027e0((longlong)PTR_IMAGE_DOS_HEADER_004043d0),
       (int)CONCAT71(extraout_var, bVar2) != 0))
  {
    iVar3 = *(int *)(puVar5 + 0x3c);
    _Str1 = puVar5 + (ulonglong) * (ushort *)(puVar5 + (longlong)iVar3 + 0x14) +
            (longlong)iVar3 + 0x18;
    if (*(ushort *)(puVar5 + (longlong)iVar3 + 6) == 0)
    {
      return (char *)0x0;
    }
    pcVar1 = _Str1 + (ulonglong)(*(ushort *)(puVar5 + (longlong)iVar3 + 6) - 1) * 0x28 + 0x28;
    do
    {
      iVar3 = strncmp(_Str1, param_1, 8);
      if (iVar3 == 0)
      {
        return _Str1;
      }
      _Str1 = _Str1 + 0x28;
    } while (_Str1 != pcVar1);
    return (char *)0x0;
  }
  return (char *)0x0;
}

/* Function: FUN_00402910 */
longlong FUN_00402910(longlong param_1)

{
  undefined *puVar1;
  int iVar2;
  bool bVar3;
  undefined7 extraout_var;
  longlong lVar4;
  undefined *puVar5;
  undefined *puVar6;

  lVar4 = 0;
  if ((*(short *)PTR_IMAGE_DOS_HEADER_004043d0 == 0x5a4d) &&
      (puVar6 = PTR_IMAGE_DOS_HEADER_004043d0,
       bVar3 = FUN_004027e0((longlong)PTR_IMAGE_DOS_HEADER_004043d0),
       (int)CONCAT71(extraout_var, bVar3) != 0))
  {
    iVar2 = *(int *)(puVar6 + 0x3c);
    puVar5 = puVar6 + (ulonglong) * (ushort *)(puVar6 + (longlong)iVar2 + 0x14) +
             (longlong)iVar2 + 0x18;
    if (*(ushort *)(puVar6 + (longlong)iVar2 + 6) != 0)
    {
      puVar1 = puVar5 + (ulonglong)(*(ushort *)(puVar6 + (longlong)iVar2 + 6) - 1) * 0x28 + 0x28;
      do
      {
        if (((ulonglong) * (uint *)(puVar5 + 0xc) <= (ulonglong)(param_1 - (longlong)puVar6)) &&
            ((ulonglong)(param_1 - (longlong)puVar6) <
             (ulonglong)(*(uint *)(puVar5 + 0xc) + *(int *)(puVar5 + 8))))
        {
          return (longlong)puVar5;
        }
        puVar5 = puVar5 + 0x28;
      } while (puVar5 != puVar1);
    }
    lVar4 = 0;
  }
  return lVar4;
}

/* Function: FUN_004029a0 */
ulonglong FUN_004029a0(void)

{
  bool bVar1;
  undefined7 extraout_var;
  undefined *puVar3;
  ulonglong uVar2;

  uVar2 = 0;
  if (*(short *)PTR_IMAGE_DOS_HEADER_004043d0 == 0x5a4d)
  {
    puVar3 = PTR_IMAGE_DOS_HEADER_004043d0;
    bVar1 = FUN_004027e0((longlong)PTR_IMAGE_DOS_HEADER_004043d0);
    uVar2 = CONCAT71(extraout_var, bVar1);
    if ((int)uVar2 != 0)
    {
      uVar2 = (ulonglong) * (ushort *)(puVar3 + (longlong) * (int *)(puVar3 + 0x3c) + 6);
    }
  }
  return uVar2;
}

/* Function: FUN_004029d0 */
longlong FUN_004029d0(longlong param_1)

{
  int iVar1;
  bool bVar2;
  undefined7 extraout_var;
  undefined *puVar3;
  longlong lVar4;
  undefined *puVar5;

  lVar4 = 0;
  if ((*(short *)PTR_IMAGE_DOS_HEADER_004043d0 == 0x5a4d) &&
      (puVar3 = PTR_IMAGE_DOS_HEADER_004043d0,
       bVar2 = FUN_004027e0((longlong)PTR_IMAGE_DOS_HEADER_004043d0),
       (int)CONCAT71(extraout_var, bVar2) != 0))
  {
    iVar1 = *(int *)(puVar3 + 0x3c);
    puVar5 = puVar3 + (ulonglong) * (ushort *)(puVar3 + (longlong)iVar1 + 0x14) +
             (longlong)iVar1 + 0x18;
    if (*(ushort *)(puVar3 + (longlong)iVar1 + 6) != 0)
    {
      puVar3 = puVar5 + (ulonglong)(*(ushort *)(puVar3 + (longlong)iVar1 + 6) - 1) * 0x28 + 0x28;
      do
      {
        if ((puVar5[0x27] & 0x20) != 0)
        {
          if (param_1 == 0)
          {
            return (longlong)puVar5;
          }
          param_1 = param_1 + -1;
        }
        puVar5 = puVar5 + 0x28;
      } while (puVar5 != puVar3);
    }
    lVar4 = 0;
  }
  return lVar4;
}

/* Function: FUN_00402a40 */
IMAGE_DOS_HEADER *FUN_00402a40(void)

{
  bool bVar1;
  undefined7 extraout_var;
  IMAGE_DOS_HEADER *pIVar2;
  IMAGE_DOS_HEADER *pIVar3;

  pIVar3 = (IMAGE_DOS_HEADER *)0x0;
  if (*(short *)PTR_IMAGE_DOS_HEADER_004043d0 == 0x5a4d)
  {
    pIVar2 = (IMAGE_DOS_HEADER *)PTR_IMAGE_DOS_HEADER_004043d0;
    bVar1 = FUN_004027e0((longlong)PTR_IMAGE_DOS_HEADER_004043d0);
    if ((int)CONCAT71(extraout_var, bVar1) != 0)
    {
      pIVar3 = pIVar2;
    }
  }
  return pIVar3;
}

/* Function: FUN_00402bc0 */
ulonglong FUN_00402bc0(void)

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

/* Function: MSVCRT.DLL::_read */
int __cdecl _read(int _FileHandle, void *_DstBuf, uint _MaxCharCount)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c00. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = _read(_FileHandle, _DstBuf, _MaxCharCount);
  return iVar1;
}

/* Function: MSVCRT.DLL::vfprintf */
int __cdecl vfprintf(FILE *_File, char *_Format, va_list _ArgList)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c08. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = vfprintf(_File, _Format, _ArgList);
  return iVar1;
}

/* Function: MSVCRT.DLL::strncmp */
int __cdecl strncmp(char *_Str1, char *_Str2, size_t _MaxCount)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c10. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = strncmp(_Str1, _Str2, _MaxCount);
  return iVar1;
}

/* Function: MSVCRT.DLL::strlen */
size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;

  /* WARNING: Could not recover jumptable at 0x00402c18. Too many branches */
  /* WARNING: Treating indirect jump as call */
  sVar1 = strlen(_Str);
  return sVar1;
}

/* Function: MSVCRT.DLL::signal */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void signal(int param_1)

{
  /* WARNING: Could not recover jumptable at 0x00402c20. Too many branches */
  /* WARNING: Treating indirect jump as call */
  signal(param_1);
  return;
}

/* Function: MSVCRT.DLL::puts */
int __cdecl puts(char *_Str)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c28. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = puts(_Str);
  return iVar1;
}

/* Function: MSVCRT.DLL::memcpy */
void *__cdecl memcpy(void *_Dst, void *_Src, size_t _Size)

{
  void *pvVar1;

  /* WARNING: Could not recover jumptable at 0x00402c30. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pvVar1 = memcpy(_Dst, _Src, _Size);
  return pvVar1;
}

/* Function: MSVCRT.DLL::malloc */
void *__cdecl malloc(size_t _Size)

{
  void *pvVar1;

  /* WARNING: Could not recover jumptable at 0x00402c38. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pvVar1 = malloc(_Size);
  return pvVar1;
}

/* Function: MSVCRT.DLL::fwrite */
size_t __cdecl fwrite(void *_Str, size_t _Size, size_t _Count, FILE *_File)

{
  size_t sVar1;

  /* WARNING: Could not recover jumptable at 0x00402c40. Too many branches */
  /* WARNING: Treating indirect jump as call */
  sVar1 = fwrite(_Str, _Size, _Count, _File);
  return sVar1;
}

/* Function: MSVCRT.DLL::free */
void __cdecl free(void *_Memory)

{
  /* WARNING: Could not recover jumptable at 0x00402c48. Too many branches */
  /* WARNING: Treating indirect jump as call */
  free(_Memory);
  return;
}

/* Function: MSVCRT.DLL::fprintf */
int __cdecl fprintf(FILE *_File, char *_Format, ...)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c50. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = fprintf(_File, _Format);
  return iVar1;
}

/* Function: MSVCRT.DLL::fopen */
FILE *__cdecl fopen(char *_Filename, char *_Mode)

{
  FILE *pFVar1;

  /* WARNING: Could not recover jumptable at 0x00402c58. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pFVar1 = fopen(_Filename, _Mode);
  return pFVar1;
}

/* Function: MSVCRT.DLL::fgets */
char *__cdecl fgets(char *_Buf, int _MaxCount, FILE *_File)

{
  char *pcVar1;

  /* WARNING: Could not recover jumptable at 0x00402c60. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pcVar1 = fgets(_Buf, _MaxCount, _File);
  return pcVar1;
}

/* Function: MSVCRT.DLL::exit */
void __cdecl exit(int _Code)

{
  /* WARNING: Could not recover jumptable at 0x00402c68. Too many branches */
  /* WARNING: Subroutine does not return */
  /* WARNING: Treating indirect jump as call */
  exit(_Code);
  return;
}

/* Function: MSVCRT.DLL::calloc */
void *__cdecl calloc(size_t _Count, size_t _Size)

{
  void *pvVar1;

  /* WARNING: Could not recover jumptable at 0x00402c70. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pvVar1 = calloc(_Count, _Size);
  return pvVar1;
}

/* Function: MSVCRT.DLL::abort */
void __cdecl abort(void)

{
  /* WARNING: Could not recover jumptable at 0x00402c78. Too many branches */
  /* WARNING: Subroutine does not return */
  /* WARNING: Treating indirect jump as call */
  abort();
  return;
}

/* Function: MSVCRT.DLL::_onexit */
_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;

  /* WARNING: Could not recover jumptable at 0x00402c80. Too many branches */
  /* WARNING: Treating indirect jump as call */
  p_Var1 = _onexit(_Func);
  return p_Var1;
}

/* Function: MSVCRT.DLL::_initterm */
void _initterm(void)

{
  /* WARNING: Could not recover jumptable at 0x00402c88. Too many branches */
  /* WARNING: Treating indirect jump as call */
  _initterm();
  return;
}

/* Function: MSVCRT.DLL::_cexit */
void __cdecl _cexit(void)

{
  /* WARNING: Could not recover jumptable at 0x00402c90. Too many branches */
  /* WARNING: Treating indirect jump as call */
  _cexit();
  return;
}

/* Function: MSVCRT.DLL::_amsg_exit */
void __cdecl _amsg_exit(int param_1)

{
  /* WARNING: Could not recover jumptable at 0x00402c98. Too many branches */
  /* WARNING: Treating indirect jump as call */
  _amsg_exit(param_1);
  return;
}

/* Function: MSVCRT.DLL::__setusermatherr */
void __setusermatherr(void)

{
  /* WARNING: Could not recover jumptable at 0x00402ca0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  __setusermatherr();
  return;
}

/* Function: MSVCRT.DLL::__set_app_type */
void __cdecl __set_app_type(int param_1)

{
  /* WARNING: Could not recover jumptable at 0x00402ca8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  __set_app_type(param_1);
  return;
}

/* Function: MSVCRT.DLL::__getmainargs */
void __getmainargs(void)

{
  /* WARNING: Could not recover jumptable at 0x00402cb8. Too many branches */
  /* WARNING: Treating indirect jump as call */
  __getmainargs();
  return;
}

/* Function: FUN_00402cd0 */
FILE *FUN_00402cd0(uint param_1)

{
  FILE *pFVar1;

  pFVar1 = __iob_func();
  return pFVar1 + param_1;
}

/* Function: FUN_00402d00 */
undefined8 FUN_00402d00(undefined8 param_1)

{
  undefined8 uVar1;

  uVar1 = DAT_00407950;
  LOCK();
  DAT_00407950 = param_1;
  UNLOCK();
  return uVar1;
}

/* Function: FUN_00402d10 */
undefined *FUN_00402d10(void)

{
  return *(undefined **)PTR_PTR__acmdln_004043f0;
}

/* Function: FUN_00402d20 */
undefined *FUN_00402d20(void)

{
  return *(undefined **)PTR_PTR__fmode_00404400;
}

/* Function: MSVCRT.DLL::__iob_func */
FILE *__cdecl __iob_func(void)

{
  FILE *pFVar1;

  /* WARNING: Could not recover jumptable at 0x00402d30. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pFVar1 = __iob_func();
  return pFVar1;
}

;