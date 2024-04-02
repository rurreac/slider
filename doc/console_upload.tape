Output ./console_upload.gif

Require echo

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600

Type "./slider server" 
Enter
Sleep 1s
Ctrl+C
Sleep 2s
Type "connect 172.16.207.129:8081"
Enter
Sleep 2s
Type "sessions"
Enter
Sleep 2s
Type "echo -n 'Upload from Server' > ./upload.txt"
Enter
Sleep 2s
Type "upload -s 1 ./upload.txt"
Enter
Sleep 2s
Type "execute -s 1 ls -l ./upload.txt && cat ./upload.txt"
Enter
Sleep 5s
