package sexp

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"unicode"
)

type reader struct {
	sr *strings.Reader
}

func (r reader) readRune() (c rune) {
	c, _, err := r.sr.ReadRune()
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
	r := reader{sr}

	for {
		exp, ok, _ := parse(r)
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

func parse(r reader) (exp interface{}, ok, end bool) {
	var c rune

	for {
		c = r.readRune()
		if !unicode.IsSpace(c) {
			break
		}
	}

	switch {
	case c == '(':
		exp = parseList(r)
		ok = true

	case unicode.IsLetter(c) || c == '$' || c == '_':
		exp, end = parseSymbol(r, c)
		ok = true

	case unicode.IsDigit(c) || c == '-':
		exp, end = parseNumber(r, c)
		ok = true

	case c == '"':
		exp, end = parseString(r)
		ok = true

	case c == ')':
		end = true

	case c == ';':
		skipComment(r)

	default:
		panic(fmt.Errorf("unexpected '%c'", c))
	}

	return
}

func parseList(r reader) interface{} {
	var list []interface{}

	for {
		item, ok, end := parse(r)
		if ok {
			list = append(list, item)
		}
		if end {
			break
		}
	}

	return list
}

func parseSymbol(r reader, c rune) (exp interface{}, end bool) {
	exp, end = parseToken(r, c)
	return
}

func parseNumber(r reader, c rune) (exp interface{}, end bool) {
	s, end := parseToken(r, c)

	var err error

	if c == '-' {
		exp, err = strconv.ParseInt(s, 0, 64)
	} else {
		exp, err = strconv.ParseUint(s, 0, 64)
	}

	switch err {
	case nil:

	case strconv.ErrSyntax, strconv.ErrRange:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			panic(err)
		}
		exp = f

	default:
		panic(err)
	}

	return
}

func parseString(r reader) (exp interface{}, end bool) {
	var buf []rune

	for {
		c := r.readRune()

		if c == '"' {
			break
		}

		if c == '\\' {
			c = r.readRune()

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

	c := r.readRune()
	switch {
	case c == ')':
		end = true

	case unicode.IsSpace(c):

	default:
		panic(errors.New("trailing data after string literal"))
	}

	exp = string(buf)
	return
}

func parseToken(r reader, c rune) (s string, end bool) {
	buf := []rune{c}

	for {
		c := r.readRune()

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

func skipComment(r reader) {
	for {
		c := r.readRune()
		if c == '\n' {
			break
		}
	}
}
