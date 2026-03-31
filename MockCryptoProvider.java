import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Operaciones criptográficas simuladas para el intérprete.
 * No usa criptografía real — sirve solo para demostrar el flujo del script.
 */
public class MockCryptoProvider {

    /** SHA-256 de la entrada. Devuelve 32 bytes. */
    public byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new ScriptException("Error en OP_SHA256: " + e.getMessage());
        }
    }

    /** SHA-256 truncado a 20 bytes. Simula RIPEMD-160(SHA-256(x)) sin dependencias extra. */
    public byte[] hash160(byte[] input) {
        try {
            byte[] sha = MessageDigest.getInstance("SHA-256").digest(input);
            return Arrays.copyOfRange(sha, 0, 20);
        } catch (Exception e) {
            throw new ScriptException("Error en OP_HASH160: " + e.getMessage());
        }
    }

    /** Doble SHA-256 de la entrada. */
    public byte[] hash256(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(md.digest(input));
        } catch (Exception e) {
            throw new ScriptException("Error en OP_HASH256: " + e.getMessage());
        }
    }

    /**
     * Verifica una firma simulada.
     * La firma es válida si su contenido es exactamente "SIG:{@literal <pubKey>}".
     */
    public boolean checkSig(byte[] signature, byte[] pubKey) {
        String sig = new String(signature, StandardCharsets.UTF_8);
        String pk  = new String(pubKey,    StandardCharsets.UTF_8);
        return sig.equals("SIG:" + pk);
    }
}
