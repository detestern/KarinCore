; Хуки установщика NSIS (Tauri): служба KarinCore.
;
; Служба (karincore-helper.exe --service, LocalSystem) запускается по требованию: её стартует
; само приложение при подключении, в автозагрузке её нет. Вошедшим пользователям (IU) разрешено
; только запускать службу и узнавать её состояние; остановить или настроить её может
; только администратор.
;
; karincore-helper.exe копировать не нужно: Tauri кладёт в установку все [[bin]] пакета
; и сам удаляет их при деинсталляции.

!define KARIN_SERVICE "KarinCore"
; Одинарные кавычки: внутри нужны \" — так sc.exe получает путь с пробелами в кавычках.
!define KARIN_SERVICE_BIN '\"$INSTDIR\karincore-helper.exe\" --service'
!define KARIN_SERVICE_SDDL "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

!macro NSIS_HOOK_PREINSTALL
  ; Обновление: останавливаем службу, чтобы её файлы и xray.exe не были заняты.
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ${KARIN_SERVICE}'
  Pop $0
  Sleep 2000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Сборки до этапа 3 ставили вторую копию службы под этим именем.
  Delete "$INSTDIR\karincore-service.exe"
  ; create не сработает, если служба уже есть (обновление) — тогда config обновит путь.
  nsExec::ExecToLog '"$SYSDIR\sc.exe" create ${KARIN_SERVICE} binPath= "${KARIN_SERVICE_BIN}" start= demand DisplayName= "KarinCore"'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ${KARIN_SERVICE} binPath= "${KARIN_SERVICE_BIN}" start= demand obj= LocalSystem DisplayName= "KarinCore"'
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
