package executor

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// This streaming lexer is a dump compatibility transform, not an SQL
// authorization filter. Permissions on the isolated import account enforce
// the schema boundary, including qualified SQL and executable comments.
// Rebinding DEFINER preserves normal views/routines/triggers/events without
// allowing an uploaded dump to borrow a more privileged server identity.
func rebindDatabaseRestoreDefiners(dst io.Writer, src io.Reader) error {
	r := bufio.NewReaderSize(src, 32*1024)
	w := bufio.NewWriterSize(dst, restoreSQLWriteBufferSize)
	write := func(text string) error { _, err := w.WriteString(text); return err }
	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			return w.Flush()
		}
		if err != nil {
			return err
		}
		if b == '\'' || b == '"' || b == '`' {
			if err := copyDatabaseRestoreQuoted(w, r, b); err != nil {
				return err
			}
			continue
		}
		if b == '#' || b == '-' && databaseRestorePeek(r, "- ") || b == '-' && databaseRestorePeek(r, "-\t") || b == '-' && databaseRestorePeek(r, "-\n") || b == '-' && databaseRestorePeek(r, "-\r") {
			if err := w.WriteByte(b); err != nil {
				return err
			}
			for {
				c, err := r.ReadByte()
				if err == io.EOF {
					return w.Flush()
				}
				if err != nil {
					return err
				}
				if err := w.WriteByte(c); err != nil {
					return err
				}
				if c == '\n' {
					break
				}
			}
			continue
		}
		if b == '/' && databaseRestorePeek(r, "*") {
			_, _ = r.ReadByte()
			if err := write("/*"); err != nil {
				return err
			}
			if databaseRestorePeek(r, "!") || databaseRestorePeek(r, "M!") {
				// Versioned comments contain executable SQL. Keep their markers
				// but inspect their content just like ordinary SQL.
				continue
			}
			previous := byte(0)
			for {
				c, err := r.ReadByte()
				if err != nil {
					return errors.New("unterminated SQL comment")
				}
				if err := w.WriteByte(c); err != nil {
					return err
				}
				if previous == '*' && c == '/' {
					break
				}
				previous = c
			}
			continue
		}
		if !databaseRestoreWordByte(b) {
			if err := w.WriteByte(b); err != nil {
				return err
			}
			continue
		}
		word := []byte{b}
		for {
			peek, err := r.Peek(1)
			if err != nil || !databaseRestoreWordByte(peek[0]) {
				break
			}
			c, _ := r.ReadByte()
			word = append(word, c)
			if len(word) > len("DEFINER") {
				// Arbitrarily long hex/blob literals and unquoted tokens need
				// no buffering: after eight bytes this cannot be DEFINER.
				if err := write(string(word)); err != nil {
					return err
				}
				for {
					peek, err := r.Peek(1)
					if err != nil || !databaseRestoreWordByte(peek[0]) {
						break
					}
					c, _ := r.ReadByte()
					if err := w.WriteByte(c); err != nil {
						return err
					}
				}
				word = nil
				break
			}
		}
		if len(word) == 0 {
			continue
		}
		if !strings.EqualFold(string(word), "DEFINER") {
			if err := write(string(word)); err != nil {
				return err
			}
			continue
		}
		space, err := databaseRestoreReadSpace(r)
		if err != nil {
			return err
		}
		if !databaseRestorePeek(r, "=") {
			if err := write(string(word) + space); err != nil {
				return err
			}
			continue
		}
		_, _ = r.ReadByte()
		if _, err := databaseRestoreReadSpace(r); err != nil {
			return err
		}
		account, err := databaseRestoreReadAccountPart(r)
		if err != nil {
			return err
		}
		space, err = databaseRestoreReadSpace(r)
		if err != nil {
			return err
		}
		if databaseRestorePeek(r, "@") {
			_, _ = r.ReadByte()
			if _, err := databaseRestoreReadSpace(r); err != nil {
				return err
			}
			if _, err := databaseRestoreReadAccountPart(r); err != nil {
				return err
			}
			space, err = databaseRestoreReadSpace(r)
			if err != nil {
				return err
			}
		} else if !strings.EqualFold(account, "CURRENT_USER") && !strings.EqualFold(account, "CURRENT_USER()") {
			return errors.New("invalid SQL DEFINER account")
		}
		if err := write("DEFINER=CURRENT_USER" + space); err != nil {
			return err
		}
	}
}

func databaseRestorePeek(r *bufio.Reader, text string) bool {
	peek, err := r.Peek(len(text))
	return err == nil && string(peek) == text
}

func databaseRestoreWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '$'
}

func databaseRestoreReadSpace(r *bufio.Reader) (string, error) {
	var space strings.Builder
	for {
		peek, err := r.Peek(1)
		if err == io.EOF {
			return space.String(), nil
		}
		if err != nil {
			return "", err
		}
		if !strings.ContainsRune(" \r\n\t", rune(peek[0])) {
			return space.String(), nil
		}
		c, _ := r.ReadByte()
		space.WriteByte(c)
		if space.Len() > 4096 {
			return "", errors.New("SQL DEFINER spacing is too long")
		}
	}
}

func databaseRestoreReadAccountPart(r *bufio.Reader) (string, error) {
	peek, err := r.Peek(1)
	if err != nil {
		return "", errors.New("incomplete SQL DEFINER")
	}
	if peek[0] == '\'' || peek[0] == '"' || peek[0] == '`' {
		quote, _ := r.ReadByte()
		var account strings.Builder
		bounded := &databaseRestoreLimitedWriter{writer: &account, remaining: 1024}
		if err := copyDatabaseRestoreQuoted(bounded, r, quote); err != nil {
			return "", err
		}
		return account.String(), nil
	}
	var account strings.Builder
	for {
		peek, err := r.Peek(1)
		if err != nil {
			break
		}
		c := peek[0]
		if !databaseRestoreWordByte(c) && !strings.ContainsRune(".%()-", rune(c)) {
			break
		}
		_, _ = r.ReadByte()
		account.WriteByte(c)
		if account.Len() > 1024 {
			return "", errors.New("SQL DEFINER account is too long")
		}
	}
	if account.Len() == 0 {
		return "", errors.New("invalid SQL DEFINER account")
	}
	return account.String(), nil
}

type databaseRestoreLimitedWriter struct {
	writer    io.Writer
	remaining int
}

func (w *databaseRestoreLimitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, errors.New("SQL DEFINER account is too long")
	}
	w.remaining -= len(p)
	return w.writer.Write(p)
}

func copyDatabaseRestoreQuoted(w io.Writer, r *bufio.Reader, quote byte) error {
	if err := databaseRestoreWriteByte(w, quote); err != nil {
		return err
	}
	for {
		c, err := r.ReadByte()
		if err != nil {
			return errors.New("unterminated SQL quoted value")
		}
		if err := databaseRestoreWriteByte(w, c); err != nil {
			return err
		}
		if c == '\\' {
			escaped, err := r.ReadByte()
			if err != nil {
				return errors.New("unterminated SQL escape")
			}
			if err := databaseRestoreWriteByte(w, escaped); err != nil {
				return err
			}
			continue
		}
		if c != quote {
			continue
		}
		if databaseRestorePeek(r, string(quote)) {
			_, _ = r.ReadByte()
			if err := databaseRestoreWriteByte(w, quote); err != nil {
				return err
			}
			continue
		}
		return nil
	}
}

func databaseRestoreWriteByte(w io.Writer, b byte) error {
	if writer, ok := w.(io.ByteWriter); ok {
		return writer.WriteByte(b)
	}
	_, err := w.Write([]byte{b})
	return err
}
