package main

import (
	"regexp"
	"strconv"
	"unicode"
)

func isNumeric(s string) bool {
	if _, err := strconv.Atoi(s); err != nil {
		return false
	}
	return true
}
func toNumeric(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func findStringSubmatchMap(re *regexp.Regexp, str string) map[string]string {
	match := re.FindStringSubmatch(str)
	if match == nil {
		return nil
	}
	paramsMap := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i != 0 && name != "" {
			paramsMap[name] = match[i]
		}
	}
	return paramsMap
}

func getDigits(s string) string {
	var v []rune
	for _, c := range s {
		if !unicode.IsDigit(c) {
			break
		}
		v = append(v, c)
	}
	return string(v)
}
