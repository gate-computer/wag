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

  (func "3" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (set_local 10 (i32.const 1000))
    (block (br 0))
    (i32.const 13)
  )

  (func "4" (param i32) (param i32) (result i32)
    (i32.add
      (get_local 0)
      (i32.add
        (get_local 0)
        (i32.add
          (get_local 0)
          (i32.add
            (get_local 0)
            (i32.add
              (get_local 0)
              (i32.add
                (get_local 0)
                (i32.add
                  (get_local 0)
                  (i32.add
                    (get_local 0)
                    (i32.add
                      (get_local 0)
                      (i32.add
                        (get_local 0)
                        (i32.add
                          (get_local 0)
                          (i32.add
                            (get_local 0)
                            (i32.add
                              (get_local 0)
                              (i32.add
                                (get_local 0)
                                (i32.add
                                  (get_local 0)
                                  (i32.add
                                    (get_local 0)
                                    (i32.add
                                      (get_local 0)
                                      (i32.add
                                        (block
                                          (set_local 0 (get_local 1))
                                          (set_local 1 (i32.add (i32.const 3) (i32.const 5)))
                                          (i32.const 7)
                                        )
                                        (get_local 1)
                                      )
                                    )
                                  )
                                )
                              )
                            )
                          )
                        )
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    )
  )
)

(assert_return (invoke "0") (i32.const 10))
(assert_return (invoke "1") (i32.const 11))
(assert_return (invoke "2") (i32.const 12))
(assert_return (invoke "3") (i32.const 13))
(assert_return (invoke "4" (i32.const 2) (i32.const 500)) (i32.const 49))
