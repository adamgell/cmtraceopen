!include FileFunc.nsh

!macro CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION APPLICATION_NAME REGISTRY_STEM
  DeleteRegValue HKCU "Software\RegisteredApplications" "${APPLICATION_NAME}"
  DeleteRegKey HKCU "Software\${REGISTRY_STEM}\Capabilities"
  DeleteRegKey /ifempty HKCU "Software\${REGISTRY_STEM}"
  DeleteRegKey HKCU "Software\Classes\${REGISTRY_STEM}.LogFile"

  DeleteRegValue HKCU "Software\Classes\.log\OpenWithProgids" "${REGISTRY_STEM}.LogFile"
  DeleteRegKey /ifempty HKCU "Software\Classes\.log\OpenWithProgids"
  DeleteRegValue HKCU "Software\Classes\.lo_\OpenWithProgids" "${REGISTRY_STEM}.LogFile"
  DeleteRegKey /ifempty HKCU "Software\Classes\.lo_\OpenWithProgids"
  DeleteRegValue HKCU "Software\Classes\.log_\OpenWithProgids" "${REGISTRY_STEM}.LogFile"
  DeleteRegKey /ifempty HKCU "Software\Classes\.log_\OpenWithProgids"
  DeleteRegValue HKCU "Software\Classes\.cmtlog\OpenWithProgids" "${REGISTRY_STEM}.LogFile"
  DeleteRegKey /ifempty HKCU "Software\Classes\.cmtlog\OpenWithProgids"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/DisableUpdateChecks" $R1
  IfErrors done

  WriteRegDWORD SHCTX "Software\CMTrace Open" "DisableUpdateChecks" 1

done:
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; The updater and an installer-driven replacement keep the same product
  ; installed. Preserve the user's handler selection across both paths.
  ${If} $UpdateMode = 1
    Goto association_cleanup_done
  ${EndIf}
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "_?=" $R1
  ${IfNot} ${Errors}
    Goto association_cleanup_done
  ${EndIf}

  ; Tauri's NSIS package contains one edition. Remove only that package's
  ; runtime identity; never remove another edition or channel.
  StrCmp "${PRODUCTNAME}" "CMTrace Open" 0 association_cleanup_lite
  !insertmacro CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION "CMTrace Open" "CMTraceOpen"
  Goto association_cleanup_notify

association_cleanup_lite:
  StrCmp "${PRODUCTNAME}" "CMTrace Open Lite" 0 association_cleanup_nightly
  !insertmacro CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION "CMTrace Open Lite" "CMTraceOpenLite"
  Goto association_cleanup_notify

association_cleanup_nightly:
  StrCmp "${PRODUCTNAME}" "CMTrace Open Nightly" 0 association_cleanup_lite_nightly
  !insertmacro CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION "CMTrace Open Nightly" "CMTraceOpenNightly"
  Goto association_cleanup_notify

association_cleanup_lite_nightly:
  StrCmp "${PRODUCTNAME}" "CMTrace Open Lite Nightly" 0 association_cleanup_done
  !insertmacro CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION "CMTrace Open Lite Nightly" "CMTraceOpenLiteNightly"

association_cleanup_notify:
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0x1000, p 0, p 0)'

association_cleanup_done:
!macroend
