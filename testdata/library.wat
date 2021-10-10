(module
 (import "spectest" "print" (func $spectest_print_i32 (param i32)))
 (import "spectest" "print" (func $spectest_print_i32_i32_i32 (param i32 i32 i32)))
 (import "spectest" "print" (func $spectest_print_f32_f64 (param f32 f64)))
 (import "wag" "get_arg" (func $wag_get_arg (result i64)))
 (import "wag" "snapshot" (func $wag_snapshot (param i32)))
 (import "wag" "putns" (func $wag_putns (param i32 i32)))
 (import "wag" "benchmark_begin" (func $wag_benchmark_begin (result i64)))
 (import "wag" "benchmark_end" (func $wag_benchmark_end (param i64) (result i32)))
 (import "wag" "benchmark_barrier" (func $wag_benchmark_barrier (param i64 i64) (result i64)))

 (export "print_i32" (func $print_i32))
 (export "print_i32_i32_i32" (func $print_i32_i32_i32))
 (export "print_f32_f64" (func $print_f32_f64))
 (export "get_arg" (func $get_arg))
 (export "snapshot" (func $snapshot))
 (export "putns" (func $putns))
 (export "benchmark_begin" (func $benchmark_begin))
 (export "benchmark_end" (func $benchmark_end))
 (export "benchmark_barrier" (func $benchmark_barrier))

 (func $print_i32 (param i32)
       (call $spectest_print_i32
             (get_local 0)))

 (func $print_i32_i32_i32 (param i32 i32 i32)
       (call $spectest_print_i32_i32_i32
             (get_local 0)
             (get_local 1)
             (get_local 2)))

 (func $print_f32_f64 (param f32 f64)
       (call $spectest_print_f32_f64
             (get_local 0)
             (get_local 1)))

 (func $get_arg (result i64)
       (call $wag_get_arg))

 (func $snapshot (param $buf i32) (result i32)
       (local $ret i32)
       (set_local $ret (i32.load (get_local $buf)))
       (if (i32.eq (get_local $ret)
                   (i32.const 0))
           (then (call $wag_snapshot (get_local $buf))
                 (unreachable)))
       (if (i32.gt_s (get_local $ret)
                     (i32.const 0))
           (return (get_local $ret)))
       (i32.const 0))

 (func $putns (param i32 i32)
       (call $wag_putns
             (get_local 0)
             (get_local 1)))

 (func $benchmark_begin (result i64)
       (call $wag_benchmark_begin))

 (func $benchmark_end (param i64) (result i32)
       (call $wag_benchmark_end
             (get_local 0)))

 (func $benchmark_barrier (param i64 i64) (result i64)
       (call $wag_benchmark_barrier
             (get_local 0)
             (get_local 1)))

)
