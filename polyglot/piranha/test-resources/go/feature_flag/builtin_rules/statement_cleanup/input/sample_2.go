package a

import "fmt"

func else_if_cleanup(something bool, somethingElse bool) bool {
	disabled := exp.BoolValue("false")
	if something {
		fmt.Println("keep 1")
	} else if disabled {
		fmt.Println("remove 1")
	}

	if something {
		fmt.Println("keep 2a")
	} else if somethingElse {
		fmt.Println("keep 2b")
	} else if disabled {
		fmt.Println("remove 2")
	} else {
		fmt.Println("keep 2c")
	}

	return true
}
