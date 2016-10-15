BEGIN {
	FS = "`"
	PROCINFO["sorted_in"] = "@ind_str_asc"
}

function totitle(s,    tokens, i) {
	split(s, tokens, "_")
	s = ""
	for (i in tokens)
		s = s toupper(substr(tokens[i], 1, 1)) substr(tokens[i], 2)
	return s
}

/^\| +`.*` +\| +`0x[0-9a-f]{2}` +\|/ {
	names[$4] = $2
	sub("\\.", "_", $2)
	sub("/", "_", $2)
	symbols[$4] = totitle($2)
	immediates[$4] = $6
}

END {
	out = "gofmt > opcodes.go"

	print "package wag" | out
	print "import (" | out
	print "\"github.com/tsavola/wag/internal/opers\"" | out
	print "\"github.com/tsavola/wag/internal/types\"" | out
	print ")" | out
	print "const (" | out
	for (key in symbols) {
		print "opcode" symbols[key] " = opcode(" key ")" | out
	}
	print ")" | out
	print | out
	print "var opcodeStrings = [256]string{" | out
	for (key in symbols) {
		print "opcode" symbols[key] ": \"" names[key] "\"," | out
	}
	print "}" | out
	print | out
	print "var opcodeImpls = [256]opImpl{" | out
	for (i = 1; i <= 256; i++) {
		key = sprintf("0x%02x", i-1)
		name = names[key]
		comment = ""

		if (!name) {
			gen = "badGen"
			info = "0"
		} else if (name == "else") {
			gen = "badGen"
			info = "0"
			key = "opcode" symbols[key]
		} else if (name == "end") {
			gen = "nil"
			info = "0"
			key = "opcode" symbols[key]
		} else {
			type = ""
			type2 = ""
			category = ""
			oper = ""

			if (match(name, "^(.)(..)\\.([^/]+)", groups)) {
				type = toupper(groups[1] groups[2])
				if (groups[1] == "i")
					category = "Int"
				else if (groups[1] == "f")
					category = "Float"
				oper = totitle(groups[3])
			}

			if (match(name, "/")) {
				gen = "genConversionOp"
				match(name, "/(...)$", groups)
				type2 = toupper(groups[1])
				category = ""
			} else if (match(name, "\\.const$")) {
				gen = "genConst" type
				oper = ""
			} else if (match(name, "\\.(abs|ceil|clz|copysign|ctz|floor|nearest|neg|popcnt|sqrt|trunc)$")) {
				gen = "genUnaryOp"
			} else if (match(name, "\\.eqz$")) {
				gen = "genUnaryConditionOp"
			} else if (match(name, "\\.(add|and|max|min|mul|or|xor)$", groups)) {
				gen = "genBinaryCommuteOp"
			} else if (match(name, "\\.(div(|_s|_u)|rem_(s|u)|rotl|rotr|shl|shr_(s|u)|sub)$")) {
				gen = "genBinaryOp"
			} else if (match(name, "\\.(eq|ge(|_s|_u)|gt(|_s|_u)|le(|_s|_u)|lt(|_s|_u)|ne)$", groups)) {
				if (match(name, "\\.(eq|ne)$"))
					gen = "genBinaryConditionCommuteOp"
				else
					gen = "genBinaryConditionOp"
				oper = totitle(groups[1])
			} else if (match(name, "^(.*)\\.load(.*)$", groups)) {
				gen = "genLoadOp"
				type2 = ""
				if (groups[2] == "")
					category = totitle(groups[1])
			} else if (match(name, "^(.*)\\.store(.*)$", groups)) {
				gen = "genStoreOp"
				type2 = ""
				if (groups[2] == "")
					category = totitle(groups[1])
			} else {
				if (match(name, "^(block|loop|if)$")) {
					gen = "nil"
					comment = " // initialized by init()"
				} else {
					gen = "gen" symbols[key]
				}
				oper = ""
			}

			info = "0"

			if (type)
				info = info " | opInfo(types." type ")"
			if (type2)
				info = info " | (opInfo(types." type2 ") << 8)"
			if (oper)
				info = info " | (opInfo(opers." category oper ") << 16)"

			sub("^0 \\| ", "", info)

			key = "opcode" symbols[key]
		}

		print key ": {" gen ", " info "}," comment | out
	}
	print "}" | out
	print | out
	print "var opcodeSkips = [256]func(reader, opcode){" | out
	for (i = 1; i <= 256; i++) {
		key = sprintf("0x%02x", i-1)
		sym = "opcode" symbols[key]
		comment = ""

		if (match(names[key], "^(block|loop|if)$")) {
			skip = "nil"
			comment = " // initialized by init()"
		} else if (match(names[key], "^(br_table)$")) {
			skip = "skip" symbols[key]
		} else if (names[key] == "end") {
			skip = "nil"
		} else if (names[key] == "else") {
			skip = "badSkip"
		} else if (immediates[key]) {
			skip = "skip" totitle(immediates[key])
		} else if (symbols[key]) {
			skip = "skipNothing"
		} else {
			sym = key
			skip = "badSkip"
		}

		print sym ": " skip "," comment | out
	}
	print "}" | out
}
