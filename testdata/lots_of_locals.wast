(module
  (func "f0" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (i32.const 10)
  )

  (func "f1" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (set_local 10 (i32.const 1000))
    (i32.const 11)
  )

  (func "f2" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (block (br 0))
    (i32.const 12)
  )

  (func "f3" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (block (br 0 (i32.const 13)))
  )

  (func "f4" (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    (set_local 10 (i32.const 1000))
    (block (br 0))
    (i32.const 14)
  )

  (func "f5" (param i32) (param i32) (result i32)
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

(assert_return (invoke "f0") (i32.const 10))
(assert_return (invoke "f1") (i32.const 11))
(assert_return (invoke "f2") (i32.const 12))
(assert_return (invoke "f3") (i32.const 13))
(assert_return (invoke "f4") (i32.const 14))
(assert_return (invoke "f5" (i32.const 2) (i32.const 500)) (i32.const 49))
