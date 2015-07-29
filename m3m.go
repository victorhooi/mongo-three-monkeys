package main

import (
	"bufio"
	//"bytes"
	"crypto/sha1"
	//"encoding/binary"
	"fmt"
	//"math/rand"
	"hash/fnv"
	"net"
	"os"
	"regexp"
	"strings"
	"github.com/Yawning/cryptopan"
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}

// We can't use the simple version anymore anymore if want to except $comment fields- however, we can have it as a fast-path, if we're not redacting comments

var quoted_string_regex, _ = regexp.Compile(`(?P<comment>\$comment: )?"(?P<root>[^"]*)"(?P<trailing_characters>[,| }])`)
var Comment_placeholder string

func redact_namespaces(s string) string {
	// If the string ends in ":", it's a field-name, and we ignore it
	if strings.HasSuffix(s, ":") {
		return s
	} else {
		values := []string{}
		for _, word := range strings.Split(s, ".") {
			values = append(values, cipher_word(word))
		}
		return " " + strings.Join(values, ".")
	}
}

func remove_dollar_command(s string) string {
	return cipher_word(strings.Split(s, ".")[0]) + ".$cmd "
}



func redact_strings(s string) string {
	// We do a second regex to get rid of the quotation marks, and extract the trailing characters, as ReplaceAllStringFunc doesn't give you access so submatches.
	// Alternative is to use Trims and Contains

	n1 := quoted_string_regex.SubexpNames()
	r2 := quoted_string_regex.FindAllStringSubmatch(s, -1)[0]
	md := map[string]string{}
	for i, n := range r2 {
    	md[n1[i]] = n
	}

	result := ""
	if strings.Contains(s, `$comment`) {
		// This is an ugly hack - we temporarily put the comment in a global, so that we can put it back afterwards
		// This leaves it untouched by any intermediary redaction steps.
		Comment_placeholder = md["root"]
		result = "\"PLACEHOLDER_FOR_A_COMMENT\"" + md["trailing_characters"]
	} else {
		result = fmt.Sprintf("\"%x\"%s", sha1.Sum([]byte(s)), md["trailing_characters"])
	}
	return result
}

var wordlist = []string{"aardvark", "buffalo", "camel", "dugong", "elephant", "falcon", "gopher", "hamster", "iguana", "jaguar", "kangaroo", "llama", "mandrill", "newt", "ocelot", "panther", "quail", "rabbit", "salamander", "tapir", "umberllabird", "vervetMonkey", "wallaby", "yak", "zebra"}

//TODO - lookups using hash, and index
func cipher_word(s string) string {

//	fmt.Println(sha1.Sum([]byte(s)))
//	buf := bytes.NewBuffer(sha1.Sum([]byte(s)))
//	var blah int
//	fmt.Println(binary.Read(buf, binary.LittleEndian, blah))
//
//	var myint int
//	buf := bytes.NewBuffer(sha1.Sum([]byte(s)))
//	binary.Read(buf, binary.LittleEndian, &myint)

	/* TODO - Replace this with something a bit more crytographically secure */


	h := fnv.New32a()
	h.Write([]byte(s))
	hash := h.Sum32()

	return wordlist[hash%uint32(len(wordlist))]


	//return wordlist[rand.Intn(len(wordlist))]
}

func redact_fieldnames(s string) string {
	if strings.Contains(s, "$comment") {
		return s
	} else {
		values := []string{}
		for _, word := range strings.Split(strings.TrimRight(s, ": "), ".") {
			values = append(values, cipher_word(word))
		}
		return " " + strings.Join(values, ".") + ": "
	}
}

var testKey = []byte{21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16, 216, 152, 143, 131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2}

func remove_ip_addresses(s string) string {
	cpan, _ := cryptopan.New(testKey)
	return fmt.Sprint(cpan.Anonymize(net.ParseIP(s)))
}


func main() {
	var input_file string

	if len(os.Args) > 1 {
		input_file = os.Args[1]
	} else {
		fmt.Println("Input file not given - falling back to \"mongod.log\"")
		input_file = "mongo.log"
	}

	var blacklist []string

	if len(os.Args) > 2 {
		blacklist_file := os.Args[2]
		fmt.Println("Using blacklist file: " + blacklist_file)
		file, err := os.Open(blacklist_file)
		check(err)
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			blacklist = append(blacklist, scanner.Text())
		}
	} else {
		fmt.Println("No blacklist supplied")
	}

	file, err := os.Open(input_file)
	check(err)
	defer file.Close()

//	quoted_string_regex, _ := regexp.Compile(`"[^"]*"[,| }]`)
	/* Find all strings surrounded by double-quotes, followed by either a comma or closing curly-brace.
	We optionally capture a "$comment" at the beginning, which allows us to selectively not-redact any $comment fields.
	We also capture the comma or closing curly brace, so that we can put it back after.
	Both of the previous points are related to the fact Golang's regex implementation doesn't support lookaheads. */
//	quoted_string_regex, _ := regexp.Compile(`(\$comment: )?("[^"]*")([,| }])`)
	// We leave fieldnames beginning with $ alone (e.g. $in, $lte etc.)
	fieldname_regex, _ := regexp.Compile(` ([\w_][\w_$]*(\.[\w_][\w_$]*)*): `)
	// Special excpetion case for $cmd lines - are there any other $ operators we want special cases for?
	dollar_command_regex, _ := regexp.Compile(`([\w][\w$]*.\$cmd )`)

	// Source: Regular Expressions Cookbook (O'Reilly), Section 7.16
	ipv4_regex, _ := regexp.Compile(`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)

	namespace_regex, _ := regexp.Compile(`(\w+(\.\w+)+:?)`)

	/* Caveats
	We pretend that : is an invalid character for collection names - however, it is a valid character,.
	We assume that $comment is a string type - however, $comment can be any valid BSON type.
	Nested quotes and newlines - will also not work.
	We assume that text followed by a colon is a field-name, and that words delimited by periods are namespaces.
	However, we should verify that periods and colons can't occur in our string representation of the sha-1 hash.
	*/

	scanner := bufio.NewScanner(file)
    for scanner.Scan() {

		// TODO: Better way of handling invalid loglines.
		var message, preMessage string
		if strings.Contains(scanner.Text(), "]") {
			x := strings.SplitN(scanner.Text(), "]", 2)
			preMessage, message = x[0], x[1]

		} else {
			// TODO: Possibly save any rejected lines into an output file (e.g. reject.log)
			fmt.Println("ERROR - no \"]\" character - are you sure this is a mongod logline? Skipping this line...")
			continue
		}

		var anonymised_output string

		anonymised_output = quoted_string_regex.ReplaceAllStringFunc(message, redact_strings)
		anonymised_output = fieldname_regex.ReplaceAllStringFunc(anonymised_output, redact_fieldnames)
		anonymised_output = namespace_regex.ReplaceAllStringFunc(anonymised_output, redact_namespaces)

		if dollar_command_regex.MatchString(anonymised_output) {
			anonymised_output = dollar_command_regex.ReplaceAllStringFunc(anonymised_output, remove_dollar_command)

		}

		for _, word := range blacklist {
			anonymised_output = strings.Replace(anonymised_output, word, "XXXX", -1)
		}

		anonymised_output = strings.Replace(anonymised_output, `PLACEHOLDER_FOR_A_COMMENT`, Comment_placeholder, -1)
		anonymised_output = ipv4_regex.ReplaceAllStringFunc(anonymised_output, remove_ip_addresses)
		fmt.Println(preMessage + "]" + anonymised_output)

    }

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading input file:", err)
	}
}