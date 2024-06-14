/* Function: read */
int __cdecl read(int _FileHandle, void *_DstBuf, uint _MaxCharCount)

{
  int iVar1;

  /* WARNING: Could not recover jumptable at 0x00402c30. Too many branches */
  /* WARNING: Treating indirect jump as call */
  iVar1 = _read(_FileHandle, _DstBuf, _MaxCharCount);
  return iVar1;
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
/* Function: fgets */
char *__cdecl fgets(char *_Buf, int _MaxCount, FILE *_File)

{
  char *pcVar1;

  /* WARNING: Could not recover jumptable at 0x00402ca0. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pcVar1 = fgets(_Buf, _MaxCount, _File);
  return pcVar1;
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
/* Function: strchr */
char *__cdecl strchr(char *_Str, int _Val)

{
  char *pcVar1;

  /* WARNING: Could not recover jumptable at 0x00402c50. Too many branches */
  /* WARNING: Treating indirect jump as call */
  pcVar1 = strchr(_Str, _Val);
  return pcVar1;
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
/* Function: exit */
void __cdecl exit(int _Code)

{
  /* WARNING: Could not recover jumptable at 0x00402ca8. Too many branches */
  /* WARNING: Subroutine does not return */
  /* WARNING: Treating indirect jump as call */
  exit(_Code);
  return;
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