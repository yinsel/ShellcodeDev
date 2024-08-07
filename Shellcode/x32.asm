.model flat, c

.code shell

assume fs: nothing
GetPEB32 proc
    xor eax, eax
    mov eax, 17h
    mov eax, fs:[eax+19h]
    ret
GetPEB32 endp

GetExeBaseAddr32 proc
    call GetPEB32
    mov eax, [eax+8h]
    ret
GetExeBaseAddr32 endp

GetNtdllAddr32 proc
    call GetPEB32
    mov eax, [eax+0Ch]
    mov eax, [eax+0Ch]
    mov eax, [eax]
    mov eax, [eax+18h]
    ret
GetNtdllAddr32 endp

GetKernel32Addr32 proc
    call GetPEB32
    mov eax, [eax+0Ch]
    mov eax, [eax+0Ch]
    mov eax, [eax]
    mov eax, [eax]
    mov eax, [eax+18h]
    ret
GetKernel32Addr32 endp

end