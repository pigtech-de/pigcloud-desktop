package output

var quiet bool

func SetQuiet(q bool) { quiet = q }

func IsQuiet() bool { return quiet }
