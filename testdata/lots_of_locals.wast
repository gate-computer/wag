(module
  (func "0" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (i32.const 10)
  )

  (func "1" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (set_local 10 (i32.const 1000))
    (i32.const 11)
  )

  (func "2" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (block (br 0))
    (i32.const 12)
  )
)

(assert_return (invoke "0") (i32.const 10))
(assert_return (invoke "1") (i32.const 11))
(assert_return (invoke "2") (i32.const 12))
