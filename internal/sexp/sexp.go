package sexp

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"unicode"
)

type panicReader struct {
	sr *strings.Reader
}

func (pr panicReader) readRune() (c rune) {
	c, _, err := pr.sr.ReadRune()
	if err != nil {
		panic(err)
	}
	return
}

func (pr panicReader) unreadRune() {
	if err := pr.sr.UnreadRune(); err != nil {
		panic(err)
	}
}

func Parse(data []byte) (exp interface{}, rest []byte, err error) {
	defer func() {
		if x := recover(); x != nil {
			if err, _ = x.(error); err == nil {
				panic(x)
			}
		}
	}()

	exp, rest = ParsePanic(data)
	return
}

func ParsePanic(data []byte) (list []interface{}, rest []byte) {
	sr := strings.NewReader(string(data))
	pr := panicReader{sr}

	inComment := false

	for {
		c, _, err := sr.ReadRune()
		if err != nil {
			if err == io.EOF {
				return
			}
			panic(err)
		}

		if inComment {
			if c == '\n' {
				inComment = false
			}
		} else {
			if c == ';' {
				inComment = true
			} else if !unicode.IsSpace(c) {
				pr.unreadRune()
				break
			}
		}
	}

	for {
		exp, ok, _ := parse(pr)
		if ok {
			list = exp.([]interface{})

			var err error
			rest, err = ioutil.ReadAll(sr)
			if err != nil {
				panic(err)
			}

			return
		}
	}
}

func parse(pr panicReader) (x interface{}, ok, end bool) {
	for {
		if !unicode.IsSpace(pr.readRune()) {
			pr.unreadRune()
			break
		}
	}

	switch pr.readRune() {
	case ';':
		skipComment(pr)

	case '(':
		x = parseList(pr)
		ok = true

	case ')':
		end = true

	case '"':
		x = parseData(pr)
		ok = true

	default:
		pr.unreadRune()
		x = parseToken(pr)
		ok = true
	}

	return
}

func parseList(pr panicReader) interface{} {
	var list []interface{}

	for {
		item, ok, end := parse(pr)
		if ok {
			list = append(list, item)
		}
		if end {
			break
		}
	}

	return list
}

func parseData(pr panicReader) string {
	var buf []byte

	for {
		c := pr.readRune()

		if c == '"' {
			break
		}

		if c == '\\' {
			c1 := pr.readRune()
			c2 := pr.readRune()

			b, err := strconv.ParseUint(fmt.Sprintf("%c%c", c1, c2), 16, 8)
			if err != nil {
				panic(err)
			}

			buf = append(buf, byte(b))
		} else {
			buf = append(buf, byte(c))
		}
	}

	c := pr.readRune()

	switch {
	case c == ')':
		pr.unreadRune()

	case unicode.IsSpace(c):

	default:
		panic(errors.New("trailing data after string literal"))
	}

	return string(buf)
}

func parseToken(pr panicReader) string {
	var buf []rune

	for {
		c := pr.readRune()

		if c == ')' {
			pr.unreadRune()
			break
		}

		if c == '"' {
			panic(errors.New("invalid character inside token: '\"'"))
		}

		if unicode.IsSpace(c) {
			break
		}

		buf = append(buf, c)
	}

	return string(buf)
}

func skipComment(pr panicReader) {
	for pr.readRune() != '\n' {
	}

	pr.unreadRune()
}
