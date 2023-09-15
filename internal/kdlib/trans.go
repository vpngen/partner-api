package kdlib

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/alexsergivan/transliterator"
)

var langOverrites = map[string]map[rune]string{
	"ru": {
		0x401: "Jo",
		0x451: "jo",
		0x416: "Zh",
		0x436: "zh",
		0x419: "J",
		0x439: "j",
		0x427: "Ch",
		0x447: "ch",
		0x428: "Sh",
		0x448: "sh",
		0x429: "Sch",
		0x449: "sch",
		0x42D: "E",
		0x44D: "e",
		0x42E: "Ju",
		0x44E: "ju",
		0x42F: "Ja",
		0x44F: "ja",
	},
}

var trans = transliterator.NewTransliterator(&langOverrites)

var vocabulary = []byte("0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz")

// SanitizeFilename - prepare filename to wg client.
func SanitizeFilename(name string) string {
	userNum, after, ok := strings.Cut(name, " ")
	if ok {
		adjective, lname, ok := strings.Cut(after, " ")
		if ok {
			for _, c := range adjective {
				name = fmt.Sprintf("%s %s %s", userNum, string(c), lname)
				break
			}
		}
	}

	nameWithoutUnderscores := strings.ReplaceAll(name, " ", "_")
	transliteratedName := trans.Transliterate(nameWithoutUnderscores, "ru")

	if len(transliteratedName) > 15 {
		transliteratedName = transliteratedName[:15]
	}

	buf := make([]byte, 0, len(transliteratedName))

	for _, c := range []byte(transliteratedName) {
		if bytes.Contains(vocabulary, []byte{c}) {
			buf = append(buf, c)
		}
	}

	return string(buf) + ".conf"
}
