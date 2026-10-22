; Хуки установщика NSIS (Tauri): служба KarinCore.
;
; Служба (karincore-service.exe, LocalSystem) запускается по требованию: её стартует само
; приложение при подключении, в автозагрузке её нет. Вошедшим пользователям (IU) разрешено
; только запускать службу и узнавать её состояние; остановить или настроить её может
; только администратор.

!define KARIN_SERVICE "KarinCore"
; Бинарник службы не перечислен в ресурсах Tauri: при сборке самой службы build.rs Tauri
; проверяет ресурсы, и служба требовала бы саму себя. Поэтому его кладёт этот хук.
; Путь — от каталога хука (src-tauri/windows) к собранному helper'у.
!define KARIN_SERVICE_SRC "${__FILEDIR__}\..\target\release\karincore-helper.exe"
!define KARIN_SERVICE_SDDL "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

!macro NSIS_HOOK_PREINSTALL
  ; Обновление: останавливаем службу, чтобы её файлы и xray.exe не были заняты.
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ${KARIN_SERVICE}'
  Pop $0
  Sleep 2000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  File "/oname=$INSTDIR\karincore-service.exe" "${KARIN_SERVICE_SRC}"
  ; create не сработает, если служба уже есть (обновление) — тогда config обновит путь.
  nsExec::ExecToLog '"$SYSDIR\sc.exe" create ${KARIN_SERVICE} binPath= "\"$INSTDIR\karincore-service.exe\" --service" start= demand DisplayName= "KarinCore"'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ${KARIN_SERVICE} binPath= "\"$INSTDIR\karincore-service.exe\" --service" start= demand obj= LocalSystem DisplayName= "KarinCore"'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" description ${KARIN_SERVICE} "KarinCore VPN: starts the Xray core and sets up the tunnel when you connect in the KarinCore app."'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" sdset ${KARIN_SERVICE} ${KARIN_SERVICE_SDDL}'
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ${KARIN_SERVICE}'
  Pop $0
  Sleep 2000
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete ${KARIN_SERVICE}'
  Pop $0
  Delete "$INSTDIR\karincore-service.exe"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Конфигурация (ключи серверов) и журналы службы.
  ReadEnvStr $0 "ProgramData"
  StrCmp $0 "" +2 0
    RMDir /r "$0\KarinCore"
!macroend
