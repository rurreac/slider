# WebSocket Console Testing Guide

## What Was Fixed

The WebSocket handler now:
1. ✅ Creates PTY and terminal
2. ✅ Runs actual console command loop
3. ✅ Executes Slider commands via command registry
4. ✅ Handles terminal resize properly
5. ✅ Supports 'exit' command to close connection

## How to Test

### 1. Start the Server

```bash
./build/slider server
```

The WebSocket endpoint is available at: `ws://localhost:8080/console/ws`

### 2. Open Test Page

```bash
open test-console.html
```

### 3. What You Should See

1. **Connection**: Status should show "Connected to Slider console"
2. **Welcome message**: 
   ```
   Welcome to Slider Web Console
   Type 'help' for available commands
   Type 'exit' to close connection
   ```
3. **Prompt**: `slider> `

### 4. Try Commands

```
help        # List available commands
sessions    # List active sessions  
bg          # Background mode
exit        # Close WebSocket connection
```

## Key Changes Made

### Before (Not Working)
- PTY created but no command loop
- Terminal just echoed input
- No command execution

### After (Working)
- PTY → WebSocket goroutine (output)
- WebSocket → PTY goroutine (input)
- **Main loop**: Reads from terminal, parses commands, executes via registry

## Architecture

```
Browser (xterm.js)
    ↓ WebSocket
PTY Master ← → PTY Slave
    ↓           ↓
  I/O Bridge  Terminal
              ↓
          ReadLine()
              ↓
       Parse Command
              ↓
    Execute via Registry
              ↓
         Write Output
```

## Troubleshooting

**Terminal not responding?**
- Check browser console for WebSocket errors
- Verify server is running on port 8080
- Check server logs for errors

**Commands not executing?**
- Ensure command registry is initialized
- Check for error messages in terminal
- Try `help` command first

**Resize not working?**
- Check browser console for resize messages
- Verify JSON format: `{"type":"resize","cols":80,"rows":24}`
