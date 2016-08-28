; i32 add

(module
 (memory 16 1024)

 (func $add (param $x i32) (param $y i32) (result i32)
       (i32.add (get_local $x)
		(get_local $y)))

 (func $adder (result i32)
       (call $add
	     (call $add (i32.const 1) (i32.const 2))
	     (call $add (i32.const 0x7fffffff) (i32.const 3))))

 (export "adder" $adder)
)

(assert_return (invoke "adder") (i32.const -2147483643))
