package conf

// Slider environment variables
const (
	// ========================================
	// Console ENV VARS
	// ========================================

	// Position console shells in (0,0) if "true"
	SliderAlignConsoleShellEnvVar = "S_ALIGN_CONSOLE_SHELL"

	// ========================================
	// SSH MESSAGE ENV VARS
	// ========================================

	// Use alternate shell if "true"
	SliderAltShellEnvVar = "S_ALT_SHELL"
	// Request PTY for exec if "true"
	SliderExecPtyEnvVar = "S_EXEC_PTY"
	// Close environment variables if "true"
	SliderCloserEnvVar = "S_ENV_CLOSER"
)
