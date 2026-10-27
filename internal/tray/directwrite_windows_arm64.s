//go:build windows && arm64

#include "textflag.h"

TEXT dwriteGlyphTrampoline<>(SB), NOSPLIT|NOFRAME, $0
	FMOVD ZR, F0
	FMOVD ZR, F1
	JMP (R6)

TEXT ·dwriteGlyphTrampolineAddress(SB), NOSPLIT, $0-8
	MOVD $dwriteGlyphTrampoline<>(SB), R0
	MOVD R0, ret+0(FP)
	RET
