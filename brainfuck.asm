segment .data
handler_vector dq \
    _input_op, \
    _minus_op, \
    _print_op, \
    _plus_op, \
    _dec_ptr_op, \
    _loop_end_op, \
    _inc_ptr_op, \
    _loop_start_op

segment .text
global _start

;;; Basic functions

%define STDIN_FD  0
%define STDOUT_FD 1

%define READ_SYSCALL  0
%define WRITE_SYSCALL 1

    ;; _putchar - output a text character to stdout
    ;; args:
    ;; RAX - a text character
    ;; returns:
    ;; none
_putchar:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi

    sub rsp, 4

    mov [rsp], al

    mov rax, WRITE_SYSCALL
    mov rdi, STDOUT_FD
    mov rsi, rsp
    mov rdx, 1

    syscall

    add rsp, 4

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    ret

    ;; _getchar - read a text character from stdin
    ;; args:
    ;; none
    ;; returns:
    ;; RAX - a character
_getchar:
    push rcx
    push rdx
    push rsi
    push rdi

    sub rsp, 4

    mov rax, READ_SYSCALL
    mov rdi, STDIN_FD
    mov rsi, rsp
    mov rdx, 1

    syscall

    xor rax, rax

    mov al, [rsp]

    add rsp, 4

    pop rdi
    pop rsi
    pop rdx
    pop rcx

    ret

    ;; _strlen - count number of chars in C string
    ;; args:
    ;; RSI - pointer to string
    ;; returns:
    ;; RAX - length of the string
_strlen:
    xor rax, rax
__strlen_loop:
    cmp byte [rsi + rax], 0
    je __strlen_end

    inc rax

    jmp __strlen_loop
__strlen_end:
    ret

    ;; _memset - set all bytes of memory chunk to a certain value
    ;; args:
    ;; AL - byte value
    ;; RDX - memory chunk size (in bytes)
    ;; RDI - destination pointer
    ;; returns:
    ;; none
_memset:
    push rcx
    push rdi

    mov rcx, rdx

    rep stosb

    pop rdi
    pop rcx

    ret

;;; Interpreter
;;;
;;; In order to hold it's state, interpreter uses the following registers:
;;;
;;; RSI - instruction pointer
;;; RBX - loop stack index
;;; RCX - program end pointer
;;; RDX - flags register
;;; RBP - interpreter memory
;;; RDI - data pointer (incremented/decremented by > and < instructions respecitvely)

%define LOOP_STACK_ELEM_COUNT   1024
%define MEM_BUFFER_ADDR_BITS    16

%define MEM_BUFFER_ADDR_MASK \
    (1 << MEM_BUFFER_ADDR_BITS) - 1

%define LOOP_STACK_SIZE \
    (8 * LOOP_STACK_ELEM_COUNT)

%define TOTAL_ALLOC_SIZE \
    (1 << MEM_BUFFER_ADDR_BITS) + LOOP_STACK_SIZE

%define SKIP_LOOP_FLAG      1
%define STACK_OVERFLOW_FLAG 2

%define LOOP_END_INSN 5

    ;; _decode_next_insn - decode an instruction
    ;; args:
    ;; RSI - instruction pointer
    ;; returns:
    ;; RSI - gets incremented
    ;; RAX - offset of instruction handler
_decode_next_insn:
    lodsb
    mov ah, al

    shr al,  2
    and rax, 0304h
    or  ah,  al
    shr rax, 8

    ret

    ;; _execute_bf - this is where brainfuck execution happens
    ;; args:
    ;; RSI - program pointer
    ;; RDX - program length
    ;; returns:
    ;; none
_execute_bf:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp

    mov rcx, rdx
    add rcx, rsi

    sub rsp, TOTAL_ALLOC_SIZE
    mov rbp, rsp

    xor rax, rax
    mov rdx, TOTAL_ALLOC_SIZE
    mov rdi, rbp

    call _memset

    xor rbx, rbx
    xor rdx, rdx
    xor rdi, rdi
__interpreter_loop:
    cmp rsi, rcx
    je __interpreter_exit

    call _decode_next_insn

    cmp rax, LOOP_END_INSN
    jne __check_skip_flag

    and rdx, ~SKIP_LOOP_FLAG

    jmp __execute_insn
__check_skip_flag:
    test rdx, SKIP_LOOP_FLAG
    jnz __interpreter_loop
__execute_insn:
    call [handler_vector + 8 * rax]

    test rdx, STACK_OVERFLOW_FLAG
    jnz __interpreter_exit

    jmp __interpreter_loop
__interpreter_exit:
    add rsp, TOTAL_ALLOC_SIZE

    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ret

_input_op:
    push rax

    call _getchar

    mov [rbp + LOOP_STACK_SIZE + rdi], al

    pop rax

    ret

_print_op:
    push rax

    mov al, [rbp + LOOP_STACK_SIZE + rdi]

    call _putchar

    pop rax

    ret

_plus_op:
    inc byte [rbp + LOOP_STACK_SIZE + rdi]
    ret

_minus_op:
    dec byte [rbp + LOOP_STACK_SIZE + rdi]
    ret

_inc_ptr_op:
    inc rdi
    and rdi, MEM_BUFFER_ADDR_MASK

    ret

_dec_ptr_op:
    dec rdi
    and rdi, MEM_BUFFER_ADDR_MASK

    ret

_loop_start_op:
    cmp rbx, LOOP_STACK_ELEM_COUNT
    je __loop_start_of

    cmp byte [rbp + LOOP_STACK_SIZE + rdi], 0
    jne __loop_start_stack_push

    or rdx, SKIP_LOOP_FLAG
__loop_start_stack_push:
    mov [rbp + 8 * rbx], rsi

    inc rbx

    ret
__loop_start_of:
    or rdx, STACK_OVERFLOW_FLAG
    ret

_loop_end_op:
    cmp rbx, 0
    je __loop_end_of

    cmp byte [rbp + LOOP_STACK_SIZE + rdi], 0
    je __loop_end_zf

    mov rsi, [rbp + 8 * (rbx - 1)]

    ret
__loop_end_zf:
    dec rbx
    ret
__loop_end_of:
    or rdx, STACK_OVERFLOW_FLAG
    ret

;;; Launch

_start:
    cmp dword [rsp], 2
    jne __exit

    mov rsi, [rsp + 16]

    call _strlen

    mov rdx, rax

    call _execute_bf
__exit:
    mov rax, 3Ch
    xor rdi, rdi

    syscall
