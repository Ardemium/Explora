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