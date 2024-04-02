Output ./console_certs.gif

Require echo

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600

Type "./slider server -auth" 
Enter
Sleep 2s
Ctrl+C
Sleep 2s
Type "certs"
Enter
Sleep 2s
Up 1
Type " -n"
Enter
Sleep 2s
Type "connect 172.16.207.129:8081"
Enter
Sleep 2s
Type "certs"
Enter
Sleep 2s
Type "sessions"
Enter
Sleep 5s
