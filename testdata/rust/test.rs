// rustc --target=wasm32-unknown-unknown -C opt-level=z -o test.wasm test.rs

#![no_std]
#![feature(panic_implementation)]
#![feature(start)]

extern "C" {
    fn write(fd: i32, data: *const u8, size: usize);
    fn _exit(status: i32) -> !;
}

#[start]
pub fn main(_argc: isize, _argv: *const *const u8) -> isize {
    let s = "hello, world\n";
    unsafe { write(0, s.as_ptr(), s.len()) }
    0
}

#[no_mangle]
#[panic_implementation]
pub fn panic_fmt(_info: &::core::panic::PanicInfo) -> ! {
    let s = "panic\n";
    unsafe {
        write(0, s.as_ptr(), s.len());
        _exit(99)
    }
}
