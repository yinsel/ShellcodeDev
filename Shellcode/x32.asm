.model flat, c

.code shell

assume fs: nothing
GetPEB32 proc
    xor eax, eax
    mov eax, fs:[30h]
    mov eax, [eax+0Ch]
    ret
GetPEB32 endp

GetExeBase32 proc
    call GetPEB32
    mov eax, [eax+0Ch]
    mov eax, [eax+18h]
    ret
GetExeBase32 endp

GetNtdllAddr32 proc
    call GetPEB32
    mov eax, [eax+0Ch]
    mov eax, [eax]
    mov eax, [eax+18h]
    ret
GetNtdllAddr32 endp

GetKernel32Addr32 proc
    call GetPEB32
    mov eax, [eax+0Ch]
    mov eax, [eax]
    mov eax, [eax]
    mov eax, [eax+18h]
    ret
GetKernel32Addr32 endp

end