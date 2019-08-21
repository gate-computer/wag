// rustc --target=wasm32-unknown-unknown --crate-type=cdylib -C opt-level=z -o test.wasm test.rs

#![no_std]

extern "C" {
    fn write(fd: i32, data: *const u8, size: usize);
    fn _exit(status: i32) -> !;
}

#[no_mangle]
pub fn main() {
    let s = "hello, world\n";
    unsafe { write(1, s.as_ptr(), s.len()) }
}

#[panic_handler]
pub fn panic_fmt(_info: &::core::panic::PanicInfo) -> ! {
    let s = "panic\n";
    unsafe {
        write(0, s.as_ptr(), s.len());
        _exit(99)
    }
}
