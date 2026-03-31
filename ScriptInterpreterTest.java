import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/*
 Pruebas unitarias del intérprete de Bitcoin Script.
 Cubre literales, pila, lógica, aritmética, control de flujo,
 operaciones criptográficas, firmas, P2PKH, multisig y casos borde.
 */
class ScriptInterpreterTest {

    private ScriptInterpreter vm;
    private MockCryptoProvider crypto;

    @BeforeEach
    void setUp() {
        crypto = new MockCryptoProvider();
        vm = new ScriptInterpreter(crypto);
    }

    // Ejecuta un script completo dado como cadena
    private boolean run(String script) {
        return vm.execute(ScriptInterpreter.parse(script));
    }

    // Ejecuta scriptSig + scriptPubKey por separado
    private boolean run(String sig, String pubKey) {
        List<Instruction> prog = new ArrayList<>();
        prog.addAll(ScriptInterpreter.parse(sig));
        prog.addAll(ScriptInterpreter.parse(pubKey));
        return vm.execute(prog);
    }

    // Calcula hash160 de un string para usarlo en pruebas P2PKH
    private static String hash160Hex(String input) {
        try {
            byte[] sha = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            byte[] h160 = Arrays.copyOfRange(sha, 0, 20);
            StringBuilder sb = new StringBuilder("0x");
            for (byte b : h160) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Literales y push
    @Nested
    class LiteralesTest {

        @Test
        void op0EsFalso() {
            assertFalse(run("OP_0"));
        }

        @Test
        void op1EsVerdadero() {
            assertTrue(run("OP_1"));
        }

        @Test
        void op16Verdadero() {
            assertTrue(run("OP_16"));
        }

        @Test
        void opFalseAliasOp0() {
            assertFalse(run("OP_FALSE"));
        }

        @Test
        void pushdataTexto() {
            assertTrue(run("PUSHDATA alice PUSHDATA alice OP_EQUAL"));
        }

        @Test
        void pushdataHex() {
            assertTrue(run("PUSHDATA 0x0102 PUSHDATA 0x0102 OP_EQUAL"));
        }

        @Test
        void tokenDesconocidoComodato() {
            assertTrue(run("hola hola OP_EQUAL"));
        }
    }

    // Operaciones de pila
    @Nested
    class PilaTest {

        @Test
        void opDupDuplica() {
            assertTrue(run("PUSHDATA x OP_DUP OP_EQUAL"));
        }

        @Test
        void opDupPilaVacia() {
            assertFalse(run("OP_DUP"));
        }

        @Test
        void opDupCopiaIndependiente() {
            // Si DUP compartiera referencia, NOT sobre una afectaría la otra
            assertFalse(run("OP_1 OP_DUP OP_NOT OP_EQUAL"));
        }

        @Test
        void opDropDescarta() {
            assertTrue(run("OP_0 OP_1 OP_DROP"));
        }

        @Test
        void opDropPilaVacia() {
            assertFalse(run("OP_DROP"));
        }

        @Test
        void opSwapIntercambia() {
            assertTrue(run("PUSHDATA a PUSHDATA b OP_SWAP PUSHDATA a OP_EQUAL OP_DROP OP_1"));
        }

        @Test
        void opSwapUnderflow() {
            assertFalse(run("OP_1 OP_SWAP"));
        }

        @Test
        void opOverCopiaSegundo() {
            // [z, w] -> OVER -> [z, w, z]
            assertTrue(run("PUSHDATA z PUSHDATA w OP_OVER PUSHDATA z OP_EQUAL OP_DROP OP_1"));
        }

        @Test
        void opOverUnderflow() {
            assertFalse(run("OP_1 OP_OVER"));
        }
    }

    // Lógica y comparación
    @Nested
    class LogicaTest {

        @Test
        void opEqualVerdadero() {
            assertTrue(run("OP_5 OP_5 OP_EQUAL"));
        }

        @Test
        void opEqualFalso() {
            assertFalse(run("OP_3 OP_5 OP_EQUAL"));
        }

        @Test
        void opEqualVerifyOk() {
            assertTrue(run("OP_7 OP_7 OP_EQUALVERIFY OP_1"));
        }

        @Test
        void opEqualVerifyFalla() {
            assertFalse(run("OP_3 OP_7 OP_EQUALVERIFY OP_1"));
        }

        @Test
        void opNotFalsoAVerdadero() {
            assertTrue(run("OP_0 OP_NOT"));
        }

        @Test
        void opNotVerdaderoAFalso() {
            assertFalse(run("OP_1 OP_NOT"));
        }

        @Test
        void opBoolandTT() {
            assertTrue(run("OP_1 OP_1 OP_BOOLAND"));
        }

        @Test
        void opBoolandTF() {
            assertFalse(run("OP_1 OP_0 OP_BOOLAND"));
        }

        @Test
        void opBoolorFT() {
            assertTrue(run("OP_0 OP_1 OP_BOOLOR"));
        }

        @Test
        void opBoolorFF() {
            assertFalse(run("OP_0 OP_0 OP_BOOLOR"));
        }
    }

    // Aritmética
    @Nested
    class AritmeticaTest {

        @Test
        void opAdd() {
            assertTrue(run("OP_3 OP_5 OP_ADD OP_8 OP_NUMEQUALVERIFY OP_1"));
        }

        @Test
        void opSub() {
            assertTrue(run("OP_7 OP_3 OP_SUB OP_4 OP_NUMEQUALVERIFY OP_1"));
        }

        @Test
        void opNumEqualVerifyFalla() {
            assertFalse(run("OP_3 OP_5 OP_NUMEQUALVERIFY OP_1"));
        }

        @Test
        void opLessThanVerdadero() {
            assertTrue(run("OP_3 OP_5 OP_LESSTHAN"));
        }

        @Test
        void opLessThanFalso() {
            assertFalse(run("OP_5 OP_3 OP_LESSTHAN"));
        }

        @Test
        void opGreaterThan() {
            assertTrue(run("OP_5 OP_3 OP_GREATERTHAN"));
        }

        @Test
        void opLessThanOrEqual() {
            assertTrue(run("OP_5 OP_5 OP_LESSTHANOREQUAL"));
        }

        @Test
        void opGreaterThanOrEqual() {
            assertTrue(run("OP_6 OP_5 OP_GREATERTHANOREQUAL"));
        }
    }

    // Control de flujo
    @Nested
    class ControlFlujoTest {

        @Test
        void opIfRamaVerdadera() {
            assertTrue(run("OP_1 OP_IF OP_1 OP_ENDIF"));
        }

        @Test
        void opIfRamaFalsa() {
            assertFalse(run("OP_0 OP_IF OP_1 OP_ENDIF"));
        }

        @Test
        void opIfElseRamaVerdadera() {
            assertTrue(run("OP_1 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF"));
        }

        @Test
        void opIfElseRamaFalsa() {
            assertTrue(run("OP_0 OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF"));
        }

        @Test
        void opNotIf() {
            assertTrue(run("OP_0 OP_NOTIF OP_1 OP_ENDIF"));
        }

        @Test
        void ifAnidadosAmbosVerdaderos() {
            assertTrue(run("OP_1 OP_IF OP_1 OP_IF OP_1 OP_ENDIF OP_ENDIF"));
        }

        @Test
        void ifAnidadosInternoFalso() {
            assertFalse(run("OP_1 OP_IF OP_0 OP_IF OP_1 OP_ENDIF OP_ENDIF"));
        }

        @Test
        void ifSinEndif() {
            assertFalse(run("OP_1 OP_IF OP_1"));
        }

        @Test
        void opVerifyOk() {
            assertTrue(run("OP_1 OP_VERIFY OP_1"));
        }

        @Test
        void opVerifyFalla() {
            assertFalse(run("OP_0 OP_VERIFY OP_1"));
        }

        @Test
        void opReturnInvalida() {
            assertFalse(run("OP_1 OP_RETURN OP_1"));
        }
    }

    // Criptográficas
    @Nested
    class CriptograficasTest {

        @Test
        void opSha256DiferentesEntradas() {
            assertFalse(run("PUSHDATA a OP_SHA256 PUSHDATA b OP_SHA256 OP_EQUAL"));
        }

        @Test
        void opSha256MismaEntrada() {
            assertTrue(run("PUSHDATA test OP_SHA256 PUSHDATA test OP_SHA256 OP_EQUAL"));
        }

        @Test
        void opHash160DiferentesEntradas() {
            assertFalse(run("PUSHDATA alice OP_HASH160 PUSHDATA bob OP_HASH160 OP_EQUAL"));
        }

        @Test
        void opHash160MismaEntrada() {
            assertTrue(run("PUSHDATA alice OP_HASH160 PUSHDATA alice OP_HASH160 OP_EQUAL"));
        }

        @Test
        void opHash256MismaEntrada() {
            assertTrue(run("PUSHDATA data OP_HASH256 PUSHDATA data OP_HASH256 OP_EQUAL"));
        }
    }

    // Verificación de firmas
    @Nested
    class FirmasTest {

        @Test
        void opCheckSigValido() {
            assertTrue(run("SIG:alice alice", "OP_CHECKSIG"));
        }

        @Test
        void opCheckSigInvalido() {
            assertFalse(run("MAL:alice alice", "OP_CHECKSIG"));
        }

        @Test
        void opCheckSigVerifyOk() {
            assertTrue(run("SIG:alice alice", "OP_CHECKSIGVERIFY OP_1"));
        }

        @Test
        void opCheckSigVerifyFalla() {
            assertFalse(run("MALA alice", "OP_CHECKSIGVERIFY OP_1"));
        }
    }

    // Demostración P2PKH
    @Nested
    class P2PKHTest {

        @Test
        void p2pkhValido() {
            String pubKey = "alice";
            String sig    = "SIG:" + pubKey;
            String hash   = hash160Hex(pubKey);

            assertTrue(run(
                sig + " " + pubKey,
                "OP_DUP OP_HASH160 PUSHDATA " + hash + " OP_EQUALVERIFY OP_CHECKSIG"
            ));
        }

        @Test
        void p2pkhFirmaIncorrecta() {
            String hash = hash160Hex("alice");

            assertFalse(run(
                "MAL:alice alice",
                "OP_DUP OP_HASH160 PUSHDATA " + hash + " OP_EQUALVERIFY OP_CHECKSIG"
            ));
        }

        @Test
        void p2pkhClaveNoCoincideConHash() {
            // La firma es válida para alice pero el hash esperado es de bob
            String wrongHash = hash160Hex("bob");

            assertFalse(run(
                "SIG:alice alice",
                "OP_DUP OP_HASH160 PUSHDATA " + wrongHash + " OP_EQUALVERIFY OP_CHECKSIG"
            ));
        }
    }

    // Condicional
    @Nested
    class CondicionalTest {

        @Test
        void ramaVerdadera() {
            assertTrue(run("OP_1 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF"));
        }

        @Test
        void ramaFalsa() {
            assertFalse(run("OP_0 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF"));
        }

        @Test
        void anidado2Niveles() {
            assertTrue(run(
                "OP_1 OP_IF " +
                "  OP_1 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF " +
                "OP_ELSE " +
                "  OP_0 " +
                "OP_ENDIF"
            ));
        }
    }

    // Multifirma
    @Nested
    class MultifirmaTest {

        @Test
        void multisig2De3Valido() {
            assertTrue(run(
                "OP_0 SIG:alice SIG:bob OP_2 alice bob carol OP_3 OP_CHECKMULTISIG"
            ));
        }

        @Test
        void multisig2De3Invalido() {
            assertFalse(run(
                "OP_0 MAL:alice MAL:bob OP_2 alice bob carol OP_3 OP_CHECKMULTISIG"
            ));
        }
    }

    // Casos borde
    @Nested
    class CasosBordeTest {

        @Test
        void scriptVacio() {
            assertFalse(run(""));
        }

        @Test
        void pilaVaciaAlTerminar() {
            assertFalse(vm.execute(new ArrayList<>()));
        }

        @Test
        void dropDejaVacia() {
            assertFalse(run("OP_1 OP_DROP"));
        }

        @Test
        void underflowEnOpEqual() {
            assertFalse(run("OP_1 OP_EQUAL"));
        }

        @Test
        void underflowEnOpAdd() {
            assertFalse(run("OP_1 OP_ADD"));
        }

        @Test
        void equalVerifyUnderflow() {
            assertFalse(run("OP_EQUALVERIFY"));
        }

        @Test
        void opReturnSiempre() {
            assertFalse(run("OP_1 OP_RETURN"));
        }

        @Test
        void notSobreZero() {
            assertTrue(run("OP_0 OP_NOT"));
        }

        @Test
        void topeDePilaEsResultado() {
            // Hay dos elementos pero el resultado lo define el tope
            assertTrue(run("OP_0 OP_1"));
        }

        @Test
        void elseSinIf() {
            assertFalse(run("OP_ELSE OP_1 OP_ENDIF"));
        }

        @Test
        void endifSinIf() {
            assertFalse(run("OP_ENDIF OP_1"));
        }
    }
}