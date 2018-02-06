


ConnectionPtrArrayOff  equ 1A0h       ; 7.2.5 offset to conection pointer array in client's session class (connection to login server is the session)

; "Markers" to scan memory for to replace with actual addresses
DumpPacketReplacement  equ 0DEADC0DEDEADC0DEh
InjectedDataAddress    equ 0DEADDA7ADEADDA7Ah
DisconnectHandlerRplc  equ 0DEAD00DCDEAD00DCh

; List of opcodes that are never directly written to sniff file (they contain other packets inside themselves)
SMSG_COMPRESSED_PACKET equ 3052h      ; 7.2.5
SMSG_MULTIPLE_PACKETS  equ 3051h      ; 7.2.5

PUSHAQ macro
    push    RAX
    push    RBX
    push    RCX
    push    RDX
    push    RBP
    push    RSI
    push    RDI
    push    R8
    push    R9
    push    R10
    push    R11
    push    R12
    push    R13
    push    R14
    push    R15
endm

POPAQ macro
    pop     R15
    pop     R14
    pop     R13
    pop     R12
    pop     R11
    pop     R10
    pop     R9
    pop     R8
    pop     RDI
    pop     RSI
    pop     RBP
    pop     RDX
    pop     RCX
    pop     RBX
    pop     RAX
endm

.code

SMSG_Hook proc

    PUSHAQ
    PUSHFQ

    ; RDI = NetClient*
    ; RBX = WowConnection*
    ; RSI = data
    ; R14 = size

    LEA     RCX, [RDI + ConnectionPtrArrayOff]
    XOR     RAX, RAX

connectionIdLoop:
    ; Find connection index by comparing pointers
    ; WoW maintains up to 4 separate connection with different
    ; zlib compression context
    CMP     RBX, [RCX + 8 * RAX]
    JZ      connectionFound
    INC     RAX
    CMP     RAX, 4
    JL      connectionIdLoop
    MOV     RAX, 0FFFFFFFFFFFFFFFFh

connectionFound:

    MOVZX   RDX, WORD PTR [RSI] ; opcode

    CMP     RDX, SMSG_MULTIPLE_PACKETS  ; skip if multiple or compressed - function calling them is recursive - each packet contained inside will go through here again
    JZ      skipPacket
    CMP     RDX, SMSG_COMPRESSED_PACKET
    JZ      skipPacket

    LEA     RCX, [RSI + 2]  ; content

    MOV     R8, R14         ; size
    SUB     R8, 2

    XOR     R9, R9          ; direction

    PUSH    RAX             ; connectionId
    PUSH    R9              ; direction
    PUSH    R8              ; size
    PUSH    RDX             ; opcode
    PUSH    RCX             ; content
    MOV     RAX, DumpPacketReplacement
    CALL    RAX ; DumpPacket
    ADD     RSP, 28h

skipPacket:
    POPFQ
    POPAQ

    ; restore original instruction
    MOVZX   R9D, WORD PTR [RSI]
    MOV     [RBP + 28h], R15
    RET

SMSG_Hook endp

SMSG_Hook_End proc

    XOR     ECX, ECX
    RET

SMSG_Hook_End endp

CMSG_Hook proc

    PUSHAQ
    PUSHFQ

    ; RDI = CDataStore*

    MOV     R8D, [RDI + 018h]   ; size
    MOV     RCX, [RDI + 08h]    ; content
    MOVZX   EDX, WORD PTR [RCX + 4] ; opcode
    CMP     R8D, 6
    JB      skipPacket_C

    XOR     R9, R9              ; direction
    INC     R9

    ADD     RCX, 6              ; inc content to skip opcode
    SUB     R8D, 6              ; decrease size to skip opcode

    XOR     RAX, RAX
    MOV     EAX, R15D           ; connection index

    PUSH    RAX
    PUSH    R9
    PUSH    R8
    PUSH    RDX
    PUSH    RCX

    MOV     RAX, DumpPacketReplacement
    CALL    RAX                 ; DumpPacket
    ADD     RSP, 28h

skipPacket_C:
    POPFQ
    POPAQ

    ; original instructions
    MOV     RCX, RDI
    MOV     R8D, R15D

    RET

CMSG_Hook endp

CMSG_Hook_End proc

    XOR     EBX, EBX
    RET

CMSG_Hook_End endp

CMSG_Hook2 proc

    PUSHAQ
    PUSHFQ

    MOV     RCX, [RBP - 020h]   ; content
    MOVZX   EDX, WORD PTR [RCX] ; opcode
    MOV     R8D, EAX            ; size

    XOR     R9, R9              ; direction
    INC     R9

    MOV     RDI, 0FFFFFFFFFFFFFFFFh ; connectionId - there is no 'this' for NetClient* to get connectionId from WowConnection* arg

    ADD     RCX, 2              ; inc content to skip opcode
    SUB     R8D, 2              ; decrease size to skip opcode
    CMP     R8D, 0
    JZ      skipPacket_C2

    PUSH    RDI
    PUSH    R9
    PUSH    R8
    PUSH    RDX
    PUSH    RCX

    MOV     RAX, DumpPacketReplacement
    CALL    RAX                 ; DumpPacket
    ADD     RSP, 28h

skipPacket_C2:
    POPFQ
    POPAQ

    ; original instructions
    MOV     DWORD PTR [RBP - 0Ch], 4

    RET

CMSG_Hook2 endp

CMSG_Hook2_End proc

    XOR     EAX, EAX
    RET

CMSG_Hook2_End endp

Disconnect_Hook proc

    PUSHFQ
    PUSHAQ

    MOV     RAX, DisconnectHandlerRplc  ; will be replaced by a real address when injected
    CALL    RAX

    POPAQ
    POPFQ

    MOV     DWORD PTR [RCX + 0B8h], 2

    RET

Disconnect_Hook endp

Disconnect_Hook_End proc

    XOR     EDI, EDI
    RET

Disconnect_Hook_End endp

end
