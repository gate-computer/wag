package wag

import (
	"io/ioutil"
	"testing"
)

func TestHelloWorld(t *testing.T) {
	data, err := ioutil.ReadFile("hello_world.wasm")
	if err != nil {
		panic(err)
	}

	module := loadModule(data)
	t.Logf("module = %v", module)

	function := &module.Functions[0]
	t.Logf("function = %v", function)

	result := function.execute([]interface{}{int32(1), int32(2)})
	t.Logf("result = %v", result)
}
