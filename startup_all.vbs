' NetGuard AI Suite - Silent Startup (for Windows boot / Task Scheduler)
' Launches startup_all.bat without visible console window

Set WshShell = CreateObject("WScript.Shell")
WshShell.Run Chr(34) & Replace(WScript.ScriptFullName, "startup_all.vbs", "startup_all.bat") & Chr(34), 0, False
