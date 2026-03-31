import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;

/**
 * Máquina virtual de Bitcoin Script.
 * Ejecuta instrucciones sobre una pila de byte arrays, de izquierda a derecha.
 * El script es válido si termina sin errores y el tope de la pila es verdadero.
 *
 * Se usa ArrayDeque como pila principal porque tiene push/pop en O(1)
 * y no tiene el overhead de sincronización de java.util.Stack.
 */
public class ScriptInterpreter {

    // Pila principal de datos
    private final Deque<byte[]> stack = new ArrayDeque<>();

    // Pila de control para manejar IF/ELSE/ENDIF anidados
    private final Deque<Boolean> controlStack = new ArrayDeque<>();

    private final MockCryptoProvider crypto;
    private boolean trace = false;

    /** Crea el intérprete con el proveedor criptográfico indicado. */
    public ScriptInterpreter(MockCryptoProvider crypto) {
        this.crypto = crypto;
    }

    /** Activa o desactiva el modo traza. */
    public void setTrace(boolean trace) {
        this.trace = trace;
    }

    /**
     * Ejecuta el programa y devuelve true si el script es válido.
     * Devuelve false si alguna instrucción falla o el tope de la pila es falso.
     */
    public boolean execute(List<Instruction> program) {
        stack.clear();
        controlStack.clear();

        try {
            for (int pc = 0; pc < program.size(); pc++) {
                Instruction ins = program.get(pc);
                apply(ins);
                if (trace) {
                    System.out.printf("Step %-3d %-22s -> %s%n", pc, ins.getOpcode(), stackToString());
                }
            }
        } catch (ScriptException e) {
            if (trace) System.out.println("[ERROR] " + e.getMessage());
            return false;
        }

        // Si quedaron IFs sin cerrar, el script es inválido
        if (!controlStack.isEmpty()) {
            if (trace) System.out.println("[ERROR] IF sin ENDIF");
            return false;
        }

        if (stack.isEmpty()) return false;
        return asBool(stack.peek());
    }

    // Aplica una instrucción sobre la pila.
    private void apply(Instruction ins) {
        Opcode op = ins.getOpcode();

        // Verificamos si estamos en una rama activa
        boolean executing = controlStack.isEmpty() || controlStack.peek();

        // Los opcodes de control de flujo se procesan siempre para mantener el anidamiento
        switch (op) {
            case OP_IF: {
                boolean condition = false;
                if (executing) {
                    condition = asBool(popOrFail("OP_IF requiere 1 elemento"));
                }
                controlStack.push(executing && condition);
                return;
            }
            case OP_NOTIF: {
                boolean condition = false;
                if (executing) {
                    condition = !asBool(popOrFail("OP_NOTIF requiere 1 elemento"));
                }
                controlStack.push(executing && condition);
                return;
            }
            case OP_ELSE: {
                if (controlStack.isEmpty()) throw new ScriptException("OP_ELSE sin OP_IF");
                boolean current = controlStack.pop();
                boolean parentExecuting = controlStack.isEmpty() || controlStack.peek();
                controlStack.push(parentExecuting && !current);
                return;
            }
            case OP_ENDIF: {
                if (controlStack.isEmpty()) throw new ScriptException("OP_ENDIF sin OP_IF");
                controlStack.pop();
                return;
            }
            default:
                break;
        }

        // Si la rama no se está ejecutando, saltamos todo lo demás
        if (!executing) return;

        // Push de datos
        if (op == Opcode.PUSHDATA || op == Opcode.PUSHDATA1 || op == Opcode.PUSHDATA2) {
            stack.push(Arrays.copyOf(ins.getData(), ins.getData().length));
            return;
        }

        switch (op) {

            //Literales
            case OP_0: case OP_FALSE: stack.push(new byte[]{0}); break;
            case OP_1:  pushInt(1);  break;
            case OP_2:  pushInt(2);  break;
            case OP_3:  pushInt(3);  break;
            case OP_4:  pushInt(4);  break;
            case OP_5:  pushInt(5);  break;
            case OP_6:  pushInt(6);  break;
            case OP_7:  pushInt(7);  break;
            case OP_8:  pushInt(8);  break;
            case OP_9:  pushInt(9);  break;
            case OP_10: pushInt(10); break;
            case OP_11: pushInt(11); break;
            case OP_12: pushInt(12); break;
            case OP_13: pushInt(13); break;
            case OP_14: pushInt(14); break;
            case OP_15: pushInt(15); break;
            case OP_16: pushInt(16); break;

            // Pila
            case OP_DUP: {
                byte[] a = popOrFail("OP_DUP requiere 1 elemento");
                stack.push(a);
                stack.push(Arrays.copyOf(a, a.length));
                break;
            }
            case OP_DROP:
                popOrFail("OP_DROP requiere 1 elemento");
                break;

            case OP_SWAP: {
                byte[] a = popOrFail("OP_SWAP requiere 2 elementos");
                byte[] b = popOrFail("OP_SWAP requiere 2 elementos");
                stack.push(a);
                stack.push(b);
                break;
            }
            case OP_OVER: {
                // Copia el segundo elemento al tope: [b, a] -> [b, a, b]
                byte[] a = popOrFail("OP_OVER requiere 2 elementos");
                byte[] b = popOrFail("OP_OVER requiere 2 elementos");
                stack.push(b);
                stack.push(a);
                stack.push(Arrays.copyOf(b, b.length));
                break;
            }

            // Lógica y comparación
            case OP_EQUAL: {
                byte[] b = popOrFail("OP_EQUAL requiere 2 elementos");
                byte[] a = popOrFail("OP_EQUAL requiere 2 elementos");
                stack.push(boolBytes(Arrays.equals(a, b)));
                break;
            }
            case OP_EQUALVERIFY: {
                byte[] b = popOrFail("OP_EQUALVERIFY requiere 2 elementos");
                byte[] a = popOrFail("OP_EQUALVERIFY requiere 2 elementos");
                if (!Arrays.equals(a, b)) throw new ScriptException("OP_EQUALVERIFY failed");
                break;
            }
            case OP_NOT: {
                byte[] a = popOrFail("OP_NOT requiere 1 elemento");
                stack.push(boolBytes(!asBool(a)));
                break;
            }
            case OP_BOOLAND: {
                byte[] b = popOrFail("OP_BOOLAND requiere 2 elementos");
                byte[] a = popOrFail("OP_BOOLAND requiere 2 elementos");
                stack.push(boolBytes(asBool(a) && asBool(b)));
                break;
            }
            case OP_BOOLOR: {
                byte[] b = popOrFail("OP_BOOLOR requiere 2 elementos");
                byte[] a = popOrFail("OP_BOOLOR requiere 2 elementos");
                stack.push(boolBytes(asBool(a) || asBool(b)));
                break;
            }

            //Aritmética
            case OP_ADD: {
                byte[] b = popOrFail("OP_ADD requiere 2 elementos");
                byte[] a = popOrFail("OP_ADD requiere 2 elementos");
                pushInt(asInt(a) + asInt(b));
                break;
            }
            case OP_SUB: {
                // resultado = a - b (b es el tope de la pila)
                byte[] b = popOrFail("OP_SUB requiere 2 elementos");
                byte[] a = popOrFail("OP_SUB requiere 2 elementos");
                pushInt(asInt(a) - asInt(b));
                break;
            }
            case OP_NUMEQUALVERIFY: {
                byte[] b = popOrFail("OP_NUMEQUALVERIFY requiere 2 elementos");
                byte[] a = popOrFail("OP_NUMEQUALVERIFY requiere 2 elementos");
                if (asInt(a) != asInt(b)) throw new ScriptException("OP_NUMEQUALVERIFY failed");
                break;
            }
            case OP_LESSTHAN: {
                byte[] b = popOrFail("OP_LESSTHAN requiere 2 elementos");
                byte[] a = popOrFail("OP_LESSTHAN requiere 2 elementos");
                stack.push(boolBytes(asInt(a) < asInt(b)));
                break;
            }
            case OP_GREATERTHAN: {
                byte[] b = popOrFail("OP_GREATERTHAN requiere 2 elementos");
                byte[] a = popOrFail("OP_GREATERTHAN requiere 2 elementos");
                stack.push(boolBytes(asInt(a) > asInt(b)));
                break;
            }
            case OP_LESSTHANOREQUAL: {
                byte[] b = popOrFail("OP_LESSTHANOREQUAL requiere 2 elementos");
                byte[] a = popOrFail("OP_LESSTHANOREQUAL requiere 2 elementos");
                stack.push(boolBytes(asInt(a) <= asInt(b)));
                break;
            }
            case OP_GREATERTHANOREQUAL: {
                byte[] b = popOrFail("OP_GREATERTHANOREQUAL requiere 2 elementos");
                byte[] a = popOrFail("OP_GREATERTHANOREQUAL requiere 2 elementos");
                stack.push(boolBytes(asInt(a) >= asInt(b)));
                break;
            }

            // Control de flujo
            case OP_VERIFY: {
                byte[] a = popOrFail("OP_VERIFY requiere 1 elemento");
                if (!asBool(a)) throw new ScriptException("OP_VERIFY failed");
                break;
            }
            case OP_RETURN:
                throw new ScriptException("OP_RETURN: script terminado inválidamente");

            // Criptográficas
            case OP_SHA256:
                stack.push(crypto.sha256(popOrFail("OP_SHA256 requiere 1 elemento")));
                break;
            case OP_HASH160:
                stack.push(crypto.hash160(popOrFail("OP_HASH160 requiere 1 elemento")));
                break;
            case OP_HASH256:
                stack.push(crypto.hash256(popOrFail("OP_HASH256 requiere 1 elemento")));
                break;

            // Firmas
            case OP_CHECKSIG: {
                byte[] pubKey = popOrFail("OP_CHECKSIG requiere <sig> <pubKey>");
                byte[] sig    = popOrFail("OP_CHECKSIG requiere <sig> <pubKey>");
                stack.push(boolBytes(crypto.checkSig(sig, pubKey)));
                break;
            }
            case OP_CHECKSIGVERIFY: {
                byte[] pubKey = popOrFail("OP_CHECKSIGVERIFY requiere <sig> <pubKey>");
                byte[] sig    = popOrFail("OP_CHECKSIGVERIFY requiere <sig> <pubKey>");
                if (!crypto.checkSig(sig, pubKey)) throw new ScriptException("OP_CHECKSIGVERIFY failed");
                break;
            }

            // Multifirma
            case OP_CHECKMULTISIG:
                stack.push(boolBytes(executeMultiSig()));
                break;
            case OP_CHECKMULTISIGVERIFY:
                if (!executeMultiSig()) throw new ScriptException("OP_CHECKMULTISIGVERIFY failed");
                break;

            default:
                throw new ScriptException("Opcode no implementado: " + op);
        }
    }

    // Lógica de OP_CHECKMULTISIG (m de n).
    private boolean executeMultiSig() {
        int n = asInt(popOrFail("CHECKMULTISIG: falta n"));
        if (n < 0 || n > 20) throw new ScriptException("CHECKMULTISIG: n fuera de rango");

        List<byte[]> pubKeys = new ArrayList<>();
        for (int i = 0; i < n; i++) pubKeys.add(popOrFail("CHECKMULTISIG: falta pubKey"));

        int m = asInt(popOrFail("CHECKMULTISIG: falta m"));
        if (m < 0 || m > n) throw new ScriptException("CHECKMULTISIG: m fuera de rango");

        List<byte[]> sigs = new ArrayList<>();
        for (int i = 0; i < m; i++) sigs.add(popOrFail("CHECKMULTISIG: falta sig"));

        popOrFail("CHECKMULTISIG: falta OP_0 de relleno"); // bug histórico de Bitcoin

        // Cada firma se verifica contra las claves en orden
        int sigIdx = 0, pubIdx = 0;
        while (sigIdx < sigs.size() && pubIdx < pubKeys.size()) {
            if (crypto.checkSig(sigs.get(sigIdx), pubKeys.get(pubIdx))) sigIdx++;
            pubIdx++;
        }
        return sigIdx == sigs.size();
    }

    // Helpers

    // Empuja un entero como 4 bytes little-endian.
    private void pushInt(int n) {
        stack.push(new byte[]{
            (byte)(n & 0xFF),
            (byte)((n >> 8) & 0xFF),
            (byte)((n >> 16) & 0xFF),
            (byte)((n >> 24) & 0xFF)
        });
    }

    // Interpreta un byte[] como entero con signo.
    private int asInt(byte[] v) {
        if (v.length == 0) return 0;
        if (v.length == 1) return v[0];
        int result = 0;
        int len = Math.min(v.length, 4);
        for (int i = 0; i < len; i++) result |= (v[i] & 0xFF) << (8 * i);
        return result;
    }

    // Extrae el tope de la pila o lanza excepción si está vacía.
    private byte[] popOrFail(String msg) {
        byte[] v = stack.poll();
        if (v == null) throw new ScriptException("Stack underflow: " + msg);
        return v;
    }

    // Verdadero si el array no está vacío y tiene al menos un byte distinto de 0.
    private boolean asBool(byte[] v) {
        if (v.length == 0) return false;
        for (byte b : v) if (b != 0) return true;
        return false;
    }

    // Convierte un booleano a su representación en bytes ({1} o {0}).
    private byte[] boolBytes(boolean b) {
        return new byte[]{(byte)(b ? 1 : 0)};
    }

    // Representación del estado de la pila
    private String stackToString() {
        List<byte[]> list = new ArrayList<>(stack);
        StringBuilder sb = new StringBuilder("[TOP");
        for (int i = 0; i < list.size(); i++) {
            sb.append(i == 0 ? " " : ", ");
            sb.append(pretty(list.get(i)));
        }
        return sb.append("]").toString();
    }

    // Muestra el valor como string si es imprimible, o como hex si no.
    private String pretty(byte[] v) {
        String s = new String(v, StandardCharsets.UTF_8);
        for (char c : s.toCharArray()) {
            if (c != 9 && c != 10 && c != 13 && !(c >= 32 && c <= 126))
                return "0x" + toHex(v);
        }
        return s.isEmpty() ? "0x" + toHex(v) : "\"" + s + "\"";
    }

    private String toHex(byte[] v) {
        StringBuilder sb = new StringBuilder();
        for (byte b : v) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // Parser

    /**
     * Convierte una cadena de script en una lista de instrucciones.
     * Tokens separados por espacios. Si el token no es un opcode conocido,
     * se trata como dato y se empuja directamente.
     *
     * @param script cadena con el script a parsear
     * @return lista de instrucciones lista para ejecutar
     */
    public static List<Instruction> parse(String script) {
        List<Instruction> program = new ArrayList<>();
        if (script == null || script.isBlank()) return program;

        String[] tokens = script.trim().split("\\s+");

        for (int i = 0; i < tokens.length; i++) {
            String t = tokens[i];

            // PUSHDATA <dato>
            if (t.equalsIgnoreCase("PUSHDATA") || t.equalsIgnoreCase("PUSHDATA1") || t.equalsIgnoreCase("PUSHDATA2")) {
                if (i + 1 >= tokens.length) throw new ScriptException(t + " necesita un dato después");
                program.add(Instruction.push(parseData(tokens[++i])));
                continue;
            }

            // Opcode conocido
            try {
                program.add(Instruction.op(Opcode.valueOf(t.toUpperCase())));
                continue;
            } catch (IllegalArgumentException ignored) {}

            // Fallback: dato directo
            program.add(Instruction.push(parseData(t)));
        }

        return program;
    }

    // Convierte un token a bytes: hex si empieza con 0x, UTF-8 si no.
    private static byte[] parseData(String token) {
        if (token.startsWith("0x") || token.startsWith("0X"))
            return hexToBytes(token.substring(2));
        return token.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0) throw new ScriptException("Hex inválido: longitud impar");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new ScriptException("Hex inválido");
            out[i] = (byte)((hi << 4) + lo);
        }
        return out;
    }
}
