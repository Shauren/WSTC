.386
.model flat

ConnectionPtrArrayOff  equ 188h       ; 7.2.5 offset to conection pointer array in client's session class (connection to login server is the session)

; "Markers" to scan memory for to replace with actual addresses
DumpPacketReplacement  equ 0DEADC0DEh
InjectedDataAddress    equ 0DEADDA7Ah
DisconnectHandlerRplc  equ 0DEAD00DCh

; List of opcodes that are never directly written to sniff file (they contain other packets inside themselves)
SMSG_COMPRESSED_PACKET equ 3052h      ; 7.2.5
SMSG_MULTIPLE_PACKETS  equ 3051h      ; 7.2.5

.code

SMSG_Hook proc

    PUSHFD
    PUSHAD

    ; entry register status
    ; ESI: NetClient*
    ; [ebp+arg_0]: WowConnection*
    ; [ebp+arg_C]: size
    ; EBX: data pointer

    LEA     ECX, [ESI + ConnectionPtrArrayOff]
    MOV     ESI, EBX
    MOV     EBX, [EBP + 14h]
    MOV     EDI, [EBP + 8h]
    XOR     EAX, EAX

connectionIdLoop:
    ; Find connection index by comparing pointers
    ; WoW maintains up to 4 separate connection with different
    ; zlib compression context
    CMP     EDI, [ECX + 4 * EAX]
    JZ      connectionFound
    INC     EAX
    CMP     EAX, 4
    JL      connectionIdLoop
    MOV     EAX, 0FFFFFFFFh

connectionFound:

    ; actual code that mostly doesn't change
    MOVZX   ECX, WORD PTR [ESI]
    CMP     ECX, SMSG_MULTIPLE_PACKETS  ; skip if multiple or compressed - function calling them is recursive - each packet contained inside will go through here again
    JZ      skipPacket
    CMP     ECX, SMSG_COMPRESSED_PACKET
    JZ      skipPacket

    PUSH    EAX             ; connectionId
    PUSH    0               ; direction
    ADD     ESI, 2          ; content
    SUB     EBX, 2
    PUSH    EBX             ; size
    PUSH    ECX             ; opcode
    PUSH    ESI             ; content
    MOV     EAX, DumpPacketReplacement
    CALL    EAX ; DumpPacket

skipPacket:
    POPAD
    POPFD

    MOVZX   ECX, WORD PTR [EBX]     ; restore original code
    MOV     EAX, ECX
    RET

SMSG_Hook endp

SMSG_Hook_End proc

    XOR     ECX, ECX
    RET

SMSG_Hook_End endp

; NetClient::Send(CDataStore*, CONNECTION_ID)
CMSG_Hook proc

    PUSHFD
    PUSHAD

    MOV     EDX, [EDI + 04h]            ; data
    MOVZX   EDX, WORD PTR [EDX + 04h]   ; opcode
    MOV     ECX, [EDI + 10h]            ; size
    CMP     ECX, 6
    JB      skipPacket_C
    MOV     EAX, [EDI + 04h]            ; data
    ADD     EAX, 6
    MOV     ESI, [EBP + 08h]            ; connectionId

    AND     ESI, 1                      ; connection id "fix"
    PUSH    ESI                         ; connectionId
    PUSH    1                           ; direction
    SUB     ECX, 6
    PUSH    ECX                         ; size
    PUSH    EDX                         ; opcode
    PUSH    EAX                         ; content
    MOV     EAX, DumpPacketReplacement
    CALL    EAX ; DumpPacket

skipPacket_C:
    POPAD
    POPFD

    AND     DWORD PTR [EBP - 04h], 0
    MOV     DWORD PTR [EBP + 08h], EAX

    RET

CMSG_Hook endp

CMSG_Hook_End proc

    XOR     EBX, EBX
    RET

CMSG_Hook_End endp

; NetClient::SendOnConnection
CMSG_Hook2 proc

    PUSHFD
    PUSHAD

    MOV     EAX, DWORD PTR [EBP - 18h]  ; data
    MOVZX   EDX, WORD PTR [EAX]         ; opcode
    MOV     EBX, DWORD PTR [EBP - 10h]  ; size
    CMP     EBX, 2
    JB      skipPacket_C2

    ADD     EAX, 2
    SUB     EBX, 2

    PUSH    0FFFFFFFFh                  ; connectionId
    PUSH    1                           ; direction
    PUSH    EBX                         ; size
    PUSH    EDX                         ; opcode
    PUSH    EAX                         ; content
    MOV     EAX, DumpPacketReplacement
    CALL    EAX ; DumpPacket

skipPacket_C2:
    POPAD
    POPFD

    MOV     DWORD PTR [EBP - 0Ch], 4

    RET

CMSG_Hook2 endp

CMSG_Hook2_End proc

    XOR     EAX, EAX
    RET

CMSG_Hook2_End endp

; NetClient::HandleDisconnect
Disconnect_Hook proc

    PUSHFD
    PUSHAD

    MOV     EAX, DisconnectHandlerRplc  ; will be replaced by a real address when injected
    CALL    EAX

    POPAD
    POPFD

    XOR     EAX, EAX

    RET

Disconnect_Hook endp

Disconnect_Hook_End proc

    XOR     EDI, EDI
    RET

Disconnect_Hook_End endp

end
