package main

import (
	"pigcloud/cmd"
)

var (
	version = "1.0.0"
	commit  = "dev"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}
