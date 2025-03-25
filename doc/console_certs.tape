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
Type "connect -c 1 172.16.244.1:8081"
Enter
Sleep 2s
Type "certs"
Enter
Sleep 2s
Type "certs -s 1"
Enter
Sleep 5s
