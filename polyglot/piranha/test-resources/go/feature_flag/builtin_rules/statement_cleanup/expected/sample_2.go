package a

import "fmt"

func else_if_cleanup(something bool, somethingElse bool) bool {
	if something {
		fmt.Println("keep")
	}

	if something {
		fmt.Println("keep 2a")
	} else if somethingElse {
		fmt.Println("keep 2b")
	} else {
		fmt.Println("keep 2c")
	}

	return true

}
