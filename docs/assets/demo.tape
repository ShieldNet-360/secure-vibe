# SecureVibe hero demo — records the REAL `gate` catching a typosquatted
# dependency and leaked secrets. Reproduce: `make demo-gif` (see Makefile).
#
# Output is committed as docs/assets/demo.gif.

Output docs/assets/demo.gif

Require secure-code-check

Set Shell bash
Set FontSize 17
Set Width 1100
Set Height 640
Set Padding 28
Set TypingSpeed 45ms
Set Theme { "name": "SecureVibe", "black": "#0a0e1a", "red": "#ff6b6b", "green": "#3ddc84", "yellow": "#ffd166", "blue": "#4d82ec", "magenta": "#c084fc", "cyan": "#67e8f9", "white": "#e8edfa", "brightBlack": "#6b7892", "brightRed": "#ff8787", "brightGreen": "#69f0ae", "brightYellow": "#ffe08a", "brightBlue": "#6f9bf2", "brightMagenta": "#d8b4fe", "brightCyan": "#a5f3fc", "brightWhite": "#ffffff", "background": "#0d1322", "foreground": "#e8edfa", "selection": "#1d2742", "cursor": "#4d82ec" }

# --- silent setup: clean prompt + demo workspace ---
Hide
Type "cd /tmp/sv-hero-demo" Enter
Type 'export PATH="/tmp/sv-hero-demo/bin:$PATH"' Enter
Type "export SECURE_VIBE_LIBRARY_PATH=/Users/namnc/Developer/secure-vibe" Enter
Type 'export PS1="\[\e[38;5;75m\]secure\[\e[0m\] \[\e[38;5;245m\]~/app\[\e[0m\] $ "' Enter
Type "clear" Enter
Show

Sleep 800ms
Type "# Your AI assistant just wrote these. Ship them?" Sleep 400ms Enter
Sleep 600ms
Type "cat requirements.txt config.py" Enter
Sleep 1800ms

Type "secure-code-check gate requirements.txt config.py --severity-floor high" Sleep 500ms Enter
Sleep 2600ms

Type "# Blocked before commit. No cloud, no tokens, fully offline." Sleep 400ms Enter
Sleep 2200ms
