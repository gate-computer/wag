Stack layout
------------

From low to high address:

0. A buffer for runtime-specific variables (size must be a multiple of 32).
1. Space for signal stacks and red zones (size must be a multiple of 32).
2. 240 bytes for use by trap handlers and import functions.
3. 8 bytes for trap handler return address (included in call stack).
4. 8 bytes for an extra function call (included in call stack).
5. The rest of the call stack (size must be a multiple of 8).
6. Entry function index (4 bytes padded to 8).
7. Entry function arguments (8 bytes each).

Stack pointer is initially positioned between regions 5 and 6.  Stack check in
function prologue compares stack pointer against the threshold between regions
4 and 5 (stack limit).

(Size requirements for regions 0-3 cause the total size to be a multiple of 32,
so that the stack check limit divided by 16 is an even number.  It's necessary
for the ARM64 backend's suspension check.)

