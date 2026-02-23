import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class MockCryptoProvider {

    public byte[] hash160(byte[] input) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(input);

            return Arrays.copyOfRange(hash, 0, 20);

        } catch (Exception e) {
            throw new ScriptException("Error HASH160");
        }
    }

    public boolean checkSig(byte[] signature, byte[] pubKey) {

        String sig = new String(signature, StandardCharsets.UTF_8);
        String pk = new String(pubKey, StandardCharsets.UTF_8);

        return sig.equals("SIG:" + pk);
    }
}