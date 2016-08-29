package sexp

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
				if err := sr.UnreadRune(); err != nil {
					panic(err)
				}
				break
			}
		}
	}

	pr := panicReader{sr}

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

func parse(pr panicReader) (exp interface{}, ok, end bool) {
	var c rune

	for {
		c = pr.readRune()
		if !unicode.IsSpace(c) {
			break
		}
	}

	switch {
	case c == ';':
		skipComment(pr)

	case c == '(':
		exp = parseList(pr)
		ok = true

	case c == ')':
		end = true

	case c == '"':
		exp, end = parseString(pr)
		ok = true

	default:
		exp, end = parseToken(pr, c)
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

func parseString(pr panicReader) (s string, end bool) {
	var buf []rune

	for {
		c := pr.readRune()

		if c == '"' {
			break
		}

		if c == '\\' {
			c = pr.readRune()

			switch c {
			case '"', '\\':

			case 'n':
				c = '\n'

			case 'r':
				c = '\r'

			case '0':
				c = 0

			default:
				panic(fmt.Errorf("'\\%c' in string literal not handled", c))
			}
		}

		buf = append(buf, c)
	}

	c := pr.readRune()
	switch {
	case c == ')':
		end = true

	case unicode.IsSpace(c):

	default:
		panic(errors.New("trailing data after string literal"))
	}

	s = string(buf)
	return
}

func parseToken(pr panicReader, c rune) (s string, end bool) {
	buf := []rune{c}

	for {
		c := pr.readRune()

		if c == ')' {
			end = true
			break
		}

		if unicode.IsSpace(c) {
			break
		}

		buf = append(buf, c)
	}

	s = string(buf)
	return
}

func skipComment(pr panicReader) {
	for {
		c := pr.readRune()
		if c == '\n' {
			break
		}
	}
}
