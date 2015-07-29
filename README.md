# mongo-three-monkeys
Log anonymisation tool for MongoDB logfiles.

This tool was written for Skunkworks, MongoDB's quarterly hackathon.

This is *ALPHA* and a work-in-progress - please **do** check the output after running it.

It currently writes the output to `STDOUT`.

## What It Removes

The tool currently performs the following:

1. Replace any strings in double-quotes with a SHA1 digest of the contents. This is not currently salted (but this is on the TODO)
1. Remove any fieldnames (`field_name:) or MongoDB namespaces (`database.collection`), and replace them with another word chosen from a dictionary, based on a FNV hash of the word.
1. Remove any occurrences of ``<database_name>.$cmd`.
1. Remove any words contained in a blacklist file, and replace them with `XXXX`.
1. Anonymise any IP addresses, using the [Crypto-PAn algorithm](http://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/). Note that this currently uses a hard-coded key - however, we will add functionality to supply your own key in the future.

## Usage
To run it:

```
./m3m <MONGODB_LOGFILE> <BLACKLIST>
```

Both arguments are optional - if you do not supply a `<MONGODB_LOGFILE>`, it will default to `mongod.log`.

The blacklist should be a list of words, one per line, that you want completely redacted from the output - any occurences of these words will be replaced with `XXXX` (i.e. four X characters). The blacklist file is optional.


## Known Issues
* It removes various things it's not supposed to, due to the use of regexes (e.g. things that look like namespaces, but aren't). However, it was important that we not let things leak through. Ultimately, the goal is to port the regex approach to a proper parsing approach.
* We pretend that : is an invalid character for collection names - however, it is a valid character,.
* We assume that $comment is a string type - however, $comment can be any valid BSON type.
* Nested quotes and newlines - will also not work.
* We assume that text followed by a colon is a field-name, and that words delimited by periods are namespaces.
