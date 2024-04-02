Output ./console_help.gif

Require echo

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600

Type "./slider server -verbose=debug -auth" 
Sleep 100ms  
Enter
Sleep 100ms
Ctrl+C
Sleep 1s
Type "help"
Enter
Sleep 5s
