package slog

import "slider/pkg/escseq"

func colorDebug(colorOn bool) string {
	if colorOn {
		return escseq.BlueBrightBoldText("DEBU")
	}
	return "DEBU"
}

func colorInfo(colorOn bool) string {
	if colorOn {
		return escseq.CyanBoldText("INFO")
	}
	return "INFO"
}

func colorWarn(colorOn bool) string {
	if colorOn {
		return escseq.YellowBrightBoldText("WARN")
	}
	return "WARN"
}

func colorError(colorOn bool) string {
	if colorOn {
		return escseq.RedBoldText("ERRO")
	}
	return "ERRO"
}

func colorFatal(colorOn bool) string {
	if colorOn {
		return escseq.RedBrightBoldText("FATA")
	}
	return "FATA"
}

func colorGreyOut(m string, colorOn bool) string {
	if colorOn {
		return escseq.GreyBoldText(m)
	}
	return m
}
