Stack layout
------------

From smaller to larger address:

0. 16 bytes for variables (current memory pages; 4 bytes).
1. Signal stack (size must be multiple of 16 bytes).
2. 128 bytes for use by trap handler and import function implementations.
3. 16 bytes for function call and stack check trap handler call.
4. Call stack (size must be multiple of 8 bytes).
5. Entry function index (4 bytes aligned to 8 bytes).
6. Entry function arguments (8 bytes each).

Stack pointer is initially positioned between 4 and 5.  Stack check in function
prologue compares stack pointer against the threshold between 3 and 4 (stack
limit).

