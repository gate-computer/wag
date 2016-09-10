(module
  (func "br" (result i32)
    (block $out
      (i32.add
        (i32.const 0)
        (if (i32.const 1)
          (block
            (br $out (i32.const 20))
            (i32.const 1)
          )
          (i32.const 2)
        )
      )
      (i32.const 10)
    )
  )

  (func "br_table" (param i32) (result i32)
    (loop $out $loop
      (i32.add
        (i32.const 0)
        (if (i32.const 1)
          (block
            (br_table $loop $out 0 (i32.const 20) (get_local 0))
            (i32.const 1)
          )
          (i32.const 2)
        )
      )
      (i32.const 10)
    )
  )

  (func "br_table_default_delta" (param i32) (result i32)
    (loop $out $loop
      (i32.add
        (i32.const 0)
        (if (i32.const 1)
          (block
            (br_table $loop $out $loop (i32.const 20) (get_local 0))
            (i32.const 1)
          )
          (i32.const 2)
        )
      )
      (i32.const 10)
    )
  )
)

(assert_return (invoke "br") (i32.const 20))
(assert_return (invoke "br_table" (i32.const 1)) (i32.const 20))
(assert_return (invoke "br_table_default_delta" (i32.const 1)) (i32.const 20))
