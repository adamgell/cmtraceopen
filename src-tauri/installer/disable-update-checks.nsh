!include FileFunc.nsh

!macro NSIS_HOOK_POSTINSTALL
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/DisableUpdateChecks" $R1
  IfErrors done

  WriteRegDWORD SHCTX "Software\CMTrace Open" "DisableUpdateChecks" 1

done:
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegValue SHCTX "Software\CMTrace Open" "DisableUpdateChecks"
!macroend
