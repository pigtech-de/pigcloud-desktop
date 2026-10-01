package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var reservedShorthands = map[string]string{
	"a": "all",
	"d": "dry-run",
	"e": "expires",
	"E": "regex",
	"f": "force",
	"F": "fixed",
	"i": "ignore-case",
	"n": "limit",
	"o": "offset",
	"P": "password",
	"q": "quiet",
	"r": "recursive",
	"t": "type",
	"u": "username",
	"v": "verbose",
}

var shorthandExceptions = map[string]string{
	"ls sort-time": "POSIX ls mimic: -t sorts by mtime",
	"ct head":      "head mimic: -n caps line count, not a result limit",
	"ct tail":      "tail mimic: -t shows last N lines; ct has no type filter",
	"tr dirs":      "tree mimic: -d lists directories only; tr has no dry run",
	"ls recursive": "POSIX ls mimic: -R recurses, lowercase -r means reverse sort in ls",
	"uk ttl":       "-t is the unlock duration; uk has no type filter",
	"xp output":    "-o is the output path; xp has no offset",
	"ac unread":    "-u filters unread events; ac has no username",
	"ch send file": "-f attaches a cloud file; send has no confirmation to force",
	"ac follow":    "tail mimic: -f follows the log; ac has no confirmation to force",
	"mn mv dest":   "-d is the destination dir; mn mv has no dry run",
}

func TestFlagShorthandConventions(t *testing.T) {
	shortByLong := map[string]string{}
	for short, long := range reservedShorthands {
		shortByLong[long] = short
	}

	seen := map[string]bool{}
	visitFlags(rootCmd, func(c *cobra.Command, f *pflag.Flag) {
		key := commandKey(c) + " " + f.Name
		seen[key] = true
		if want, ok := reservedShorthands[f.Shorthand]; ok && f.Name != want {
			if _, excused := shorthandExceptions[key]; !excused {
				t.Errorf("%s: -%s is reserved for --%s; pick another letter or add a justified exception", key, f.Shorthand, want)
			}
		}
		if want, ok := shortByLong[f.Name]; ok && f.Shorthand != want {
			if _, excused := shorthandExceptions[key]; !excused {
				t.Errorf("%s: --%s must use shorthand -%s", key, f.Name, want)
			}
		}
	})

	for key := range shorthandExceptions {
		if !seen[key] {
			t.Errorf("stale exception %q: no such command flag", key)
		}
	}
}

func visitFlags(c *cobra.Command, fn func(*cobra.Command, *pflag.Flag)) {
	if c.Hidden {
		return
	}
	c.Flags().VisitAll(func(f *pflag.Flag) { fn(c, f) })
	c.PersistentFlags().VisitAll(func(f *pflag.Flag) { fn(c, f) })
	for _, sub := range c.Commands() {
		visitFlags(sub, fn)
	}
}

func commandKey(c *cobra.Command) string {
	parts := strings.SplitN(c.CommandPath(), " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return "global"
}
