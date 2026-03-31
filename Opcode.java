/** Instrucciones soportadas por el intérprete de Bitcoin Script. */
public enum Opcode {

    // Literales
    OP_0, OP_FALSE,
    OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8,
    OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16,
    PUSHDATA, PUSHDATA1, PUSHDATA2,

    // Pila
    OP_DUP, OP_DROP, OP_SWAP, OP_OVER,

    // Lógica y comparación
    OP_EQUAL, OP_EQUALVERIFY, OP_NOT, OP_BOOLAND, OP_BOOLOR,

    // Aritmética
    OP_ADD, OP_SUB, OP_NUMEQUALVERIFY,
    OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL,

    // Control de flujo
    OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN,

    // Criptográficas (simuladas)
    OP_SHA256, OP_HASH160, OP_HASH256,

    // Firmas (simuladas)
    OP_CHECKSIG, OP_CHECKSIGVERIFY,

    // Multifirma (avanzado)
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
}
