' NetGuard AI Launcher
Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
WshShell.CurrentDirectory = FSO.GetParentFolderName(WScript.ScriptFullName)
PW = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Microsoft\WindowsApps\pythonw.exe"
If Not FSO.FileExists(PW) Then PW = "pythonw.exe"
WshShell.Run """" & PW & """ netguard.py", 0, False
