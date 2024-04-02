Output ./console_download.gif

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
Type "execute -s 1 echo -n 'Ready to download' > ./download.txt"
Enter
Sleep 2s
Type "download -s 1 ./download.txt"
Enter
Sleep 2s
Type "cat ./download.txt"
Enter
Sleep 1s
Type "download -s 1 -f ./filelist.txt"
Enter
Sleep 15s
