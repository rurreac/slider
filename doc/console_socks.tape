Output ./console_socks.gif

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
Type "sessions -i 1" 
Enter
Sleep 2s
Type "echo -n '\nGreetings from Slider\n\n' > greetings.txt"
Enter
Sleep 2s
Type "nohup python -m http.server 9000 &"
Enter
Sleep 2s
Type "exit"
Enter
Enter
Sleep 2s
Type "socks -s 1 -p 1080"
Enter
Sleep 2s
Type "sessions"
Enter
Sleep 2s
Type "proxychains -q curl -s http://localhost:9000/greetings.txt"
Enter
Sleep 2
Type "socks -k 1"
Enter
Sleep 5s
