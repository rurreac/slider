Output ./console_execute.gif

Require echo

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600

Type "./slider server" 
Enter
Sleep 2s
Ctrl+C
Sleep 2s
Type "sessions"
Enter
Sleep 2s
Type "execute -s 1 powershell -ep bypass Get-ExecutionPolicy"
Enter
Sleep 5s
