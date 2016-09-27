(module
  (memory 0 16)

  (import $print_i32 "spectest" "print" (param i32))
  (import $snapshot "wag" "snapshot" (result i32))

  (func $main (param $arg i32) (result i32)
    (local $x i32)
    (local $y i32)
    (set_local $x (i32.const 30))
    (set_local $y (i32.const 40))
    (if (i32.eq (grow_memory (i32.add (current_memory) (i32.const 1))) (i32.const -1))
      (return (i32.const -2)))
    (i32.store (i32.const 500) (i32.add (get_local $x) (i32.const 300)))
    (i32.store (i32.const 504) (i32.add (get_local $y) (i32.const 400)))
    (call_import $print_i32 (i32.const 10))
    (call $work (get_local $x) (get_local $y)))

  (func $work (param $x i32) (param $y i32) (result i32)
    (local $ret i32)
    (set_local $ret (call_import $snapshot))
    (call_import $print_i32 (i32.const 20))
    (if (i32.eq (get_local $ret) (i32.const -1))
      (block
        (call_import $print_i32 (get_local $x))
        (call_import $print_i32 (i32.load (i32.const 500)))
        (call_import $print_i32 (get_local $y))
        (call_import $print_i32 (i32.load (i32.const 504)))))
    (get_local $ret))

  (start $main)
)
