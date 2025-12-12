package utils

import (
	"io"
	"os"
	"strconv"
	"unicode/utf8"
)

// Println écrit les arguments sur stdout avec un saut de ligne
// Contrôle strict des inputs pour éviter les injections
func Println(args ...interface{}) error {
	return Fprintln(os.Stdout, args...)
}

func Fprintln(w io.Writer, args ...interface{}) error {
	buf := make([]byte, 0, 256)

	for i, arg := range args {
		if i > 0 {
			buf = append(buf, ' ')
		}

		// Conversion sécurisée selon le type
		switch v := arg.(type) {
		case string:
			buf = appendString(buf, v)
		case int:
			buf = strconv.AppendInt(buf, int64(v), 10)
		case int64:
			buf = strconv.AppendInt(buf, v, 10)
		case uint:
			buf = strconv.AppendUint(buf, uint64(v), 10)
		case uint64:
			buf = strconv.AppendUint(buf, v, 10)
		case float64:
			buf = strconv.AppendFloat(buf, v, 'f', -1, 64)
		case bool:
			buf = strconv.AppendBool(buf, v)
		case []byte:
			buf = appendBytes(buf, v)
		default:
			// Types non supportés = représentation sécurisée
			buf = append(buf, "<unsupported>"...)
		}
	}

	buf = append(buf, '\n')
	_, err := w.Write(buf)
	return err
}

// appendString filtre les caractères dangereux
func appendString(buf []byte, s string) []byte {
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)

		// Accepte uniquement les caractères imprimables et safe
		if r == utf8.RuneError {
			// Caractère invalide UTF-8
			buf = append(buf, '?')
		} else if r < 32 && r != '\t' {
			// Caractères de contrôle (sauf tab)
			buf = append(buf, '?')
		} else if r == 127 {
			// DEL
			buf = append(buf, '?')
		} else if r >= 0x80 && r <= 0x9F {
			// Contrôles C1
			buf = append(buf, '?')
		} else {
			// Caractère valide
			buf = utf8.AppendRune(buf, r)
		}

		s = s[size:]
	}
	return buf
}

// appendBytes pour les []byte
func appendBytes(buf, data []byte) []byte {
	for _, b := range data {
		// Accepte uniquement les bytes imprimables
		if b >= 32 && b < 127 {
			buf = append(buf, b)
		} else if b == '\t' {
			buf = append(buf, b)
		} else {
			buf = append(buf, '?')
		}
	}
	return buf
}

// Print version sans newline
func Print(args ...interface{}) error {
	buf := make([]byte, 0, 256)

	for i, arg := range args {
		if i > 0 {
			buf = append(buf, ' ')
		}

		switch v := arg.(type) {
		case string:
			buf = appendString(buf, v)
		case int:
			buf = strconv.AppendInt(buf, int64(v), 10)
		case int64:
			buf = strconv.AppendInt(buf, v, 10)
		case uint:
			buf = strconv.AppendUint(buf, uint64(v), 10)
		case uint64:
			buf = strconv.AppendUint(buf, v, 10)
		case float64:
			buf = strconv.AppendFloat(buf, v, 'f', -1, 64)
		case bool:
			buf = strconv.AppendBool(buf, v)
		case []byte:
			buf = appendBytes(buf, v)
		default:
			buf = append(buf, "<unsupported>"...)
		}
	}

	_, err := os.Stdout.Write(buf)
	return err
}
