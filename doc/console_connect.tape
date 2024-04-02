Output ./console_connect.gif

Require echo

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600

Type "./slider server" 
Enter
Sleep 100ms
Ctrl+C
Sleep 2s
Type "sessions"
Enter
Sleep 2s
Type "connect 172.16.207.129:8081"
Enter
Sleep 2s
Type "sessions"
Enter
Type "sessions -k 1"
Enter
Sleep 2s
Up 1
Backspace 4
Enter
Sleep 5s
