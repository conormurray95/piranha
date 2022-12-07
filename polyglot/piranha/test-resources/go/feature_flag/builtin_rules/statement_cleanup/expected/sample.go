/*
Copyright (c) 2022 Uber Technologies, Inc.

 <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 except in compliance with the License. You may obtain a copy of the License at
 <p>http://www.apache.org/licenses/LICENSE-2.0

 <p>Unless required by applicable law or agreed to in writing, software distributed under the
 License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 express or implied. See the License for the specific language governing permissions and
 limitations under the License.
*/

package main

import "fmt"

func a() bool {
	return true
}

func b() string {
	s, err := exp.StrValue("str")
	if err != nil {
		fmt.Println(err)
	}

	return s
}

func c() string {
	s, err := exp.StrValue("str")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("not enabled")
	return "prefix_" + s
}

func after_return1() string {
	return "not enabled"
}

func after_return2(a bool) string {
	if a {
		fmt.Println("not enabled")
		return "not enabled"
	}
	// delete after return needs to consider blocks
	fmt.Println("should not be removed")
	return "keep"
}

// should remove multiple statements after return
func after_return3() string {
	return "not enabled"
}

func after_return4() string {
	fmt.Println("before 1")
	fmt.Println("before 2")

	return "not enabled"
}

func empty_if(something bool) {
}

// not removing empty if as we don't want to artificially negate `condition`s
// it can be a complex condition with multiple `||` and/or `&&`
func empty_if_with_else(something bool) {
	if something {
	} else {
		fmt.Println("non empty else")
	}
}

func only_else_if(something bool) {
	if something {
		fmt.Println("only something")
	}
}

func empty_else_if(something bool, other bool) {
	if !something {
		fmt.Println("not something")
		fmt.Println("not something 2")
		fmt.Println("not something 3")
	}
}

func empty_else_if_but_else(something bool, other bool) {
	if !something {
		fmt.Println("not something")
		fmt.Println("not something 2")
		fmt.Println("not something 3")
	} else {
		fmt.Println("just else")
	}
}

func empty_else(something bool) {
	if something {
		fmt.Println("something")
	}
}

func named_return_if_false() (can bool) {
	return false
}

func named_return_if_true() (can bool) {
	fmt.Println("true")
	return true
}
