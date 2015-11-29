package wag

import (
	"io/ioutil"
	"testing"
)

func TestHelloWorld(t *testing.T) {
	test(t, "hello_world.wasm")
}

func TestLowerIfElse(t *testing.T) {
	test(t, "lower-if-else.wasm")
}

func test(t *testing.T, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	module := loadModule(data)
	t.Logf("module = %v", module)

	function := &module.Functions[0]
	t.Logf("function = %v", function)

	result := function.expr([]interface{}{int32(1), int32(2)})
	t.Logf("result = %v", result)
}
