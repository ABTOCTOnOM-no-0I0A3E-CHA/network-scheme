package syslog

/*
Eltex MES/ESR messages carry a Cisco-like mnemonic at the start of the text:

	%FACILITY-L-MNEMONIC: description

where L is a one-letter severity. The mapping below follows the Eltex
documentation (not captured from hardware). The text is kept intact; only
Severity (and App, when the header gave none) are taken from the mnemonic.
*/
var eltexSeverity = map[byte]uint8{
	'F': 0, /* fatal/emergency */
	'A': 1, /* alert */
	'C': 2, /* critical */
	'E': 3, /* error */
	'W': 4, /* warning */
	'N': 5, /* notice */
	'I': 6, /* informational */
	'D': 7, /* debug */
}

func eltex(m *Message) {
	s := m.Text
	if len(s) < 6 || s[0] != '%' {
		return
	}
	i := 1
	for i < len(s) && i <= MaxApp && isMnemonicChar(s[i]) {
		i++
	}
	fac := s[1:i]
	if fac == "" || i+2 >= len(s) || s[i] != '-' || s[i+2] != '-' {
		return
	}
	sev, ok := eltexSeverity[s[i+1]]
	if !ok {
		return
	}
	j := i + 3
	for j < len(s) && isMnemonicChar(s[j]) {
		j++
	}
	if j == i+3 || j >= len(s) || s[j] != ':' {
		return
	}
	m.Severity = sev
	if m.App == "" && len(fac) <= MaxApp {
		m.App = fac
	}
}

func isMnemonicChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}
