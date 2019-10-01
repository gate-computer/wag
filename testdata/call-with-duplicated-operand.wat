(module
  (import "spectest" "print" (func $print (param i32 i32 i32)))
  (memory $0 1)
  (data (i32.const 4) "\10\80\00\00")

  (func $main
    (call $do_it
      (i32.const 32)))

  (func $do_it (param $0 i32)
    (local $1 i32)
    (local $2 i32)

    (i32.store offset=4
      (i32.const 0)
      (tee_local $1
        (i32.sub
          (tee_local $2
            (i32.load offset=4
              (i32.const 0)))
          (i32.and
            (i32.add
              (get_local $0)
              (i32.const 23))
            (i32.const -16)))))

    (i32.store16 offset=4
      (get_local $1)
      (i32.const 1))

    (i32.store
      (get_local $1)
      (i32.add
        (get_local $0)
        (i32.const 8)))

    (call $print
      (i32.add
        (get_local $1)
        (i32.const 8))
      (get_local $0)
      (get_local $0))

    (i32.store offset=4
      (i32.const 0)
      (get_local $2)))

  (start $main)
)
