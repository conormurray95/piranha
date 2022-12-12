package a

import "fmt"

func else_if_cleanup(something bool, somethingElse bool) bool {
	if something {
		fmt.Println("keep 1")
	}

	return true
}

// FIXME WRONG
// should keep the last `else {fmt.Println("keep 2c")}``
// currently removing the else and removing the block from `keep 2c`
// func else_if_cleanup(something bool, somethingElse bool) bool {
// 	disabled := exp.BoolValue("false")
// 	if something {
// 		fmt.Println("keep 2a")
// 	} else if somethingElse {
// 		fmt.Println("keep 2b")
// 	} else if disabled {
// 		fmt.Println("remove 2")
// 	} else {
// 		fmt.Println("keep 2c")
// 	}
// 	return true
// }

func delete_var_decl_double_short_var_decl(something bool) bool {
	if something {
		disabled := false
		return disabled
	} else {
		disabled := somethingElse()
		return disabled
	}
}
