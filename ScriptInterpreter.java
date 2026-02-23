import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;

public class ScriptInterpreter {

    private final Deque<byte[]> stack = new ArrayDeque<byte[]>();
    private final MockCryptoProvider crypto;
    private boolean trace = false;

    public ScriptInterpreter(MockCryptoProvider crypto) {
        this.crypto = crypto;
    }

    public void setTrace(boolean trace) {
        this.trace = trace;
    }

    /**
     * Ejecuta el programa (scriptSig + scriptPubKey).
     * Devuelve true si termina sin error y la cima de la pila es verdadera (≠0).
     */
    public boolean execute(List<Instruction> program) {
        stack.clear();

        for (int pc = 0; pc < program.size(); pc++) {
            Instruction ins = program.get(pc);
            apply(ins);

            if (trace) {
                System.out.println("Step " + pc + " " + ins.getOpcode() + " -> " + stackToString());
            }
        }

        if (stack.isEmpty()) return false;
        return asBool(stack.peek());
    }

    private void apply(Instruction ins) {
        Opcode op = ins.getOpcode();

        // PUSHDATA: empuja bytes directos
        if (op == Opcode.PUSHDATA) {
            stack.push(ins.getData());
            return;
        }

        switch (op) {

            case OP_0:
            case OP_FALSE:
                stack.push(new byte[]{0});
                break;

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

            case OP_DUP: {
                byte[] a = popOrFail("OP_DUP requiere 1 elemento");
                stack.push(a);
                stack.push(a);
                break;
            }

            case OP_DROP: {
                popOrFail("OP_DROP requiere 1 elemento");
                break;
            }

            case OP_EQUAL: {
                byte[] b = popOrFail("OP_EQUAL requiere 2 elementos");
                byte[] a = popOrFail("OP_EQUAL requiere 2 elementos");
                stack.push(boolBytes(Arrays.equals(a, b)));
                break;
            }

            case OP_EQUALVERIFY: {
                byte[] b = popOrFail("OP_EQUALVERIFY requiere 2 elementos");
                byte[] a = popOrFail("OP_EQUALVERIFY requiere 2 elementos");
                if (!Arrays.equals(a, b)) {
                    throw new ScriptException("OP_EQUALVERIFY failed");
                }
                break;
            }

            case OP_HASH160: {
                byte[] a = popOrFail("OP_HASH160 requiere 1 elemento");
                stack.push(crypto.hash160(a));
                break;
            }

            case OP_CHECKSIG: {
                // En Script: típicamente stack ... <sig> <pubKey>
                // pop() saca primero pubKey y luego sig
                byte[] pubKey = popOrFail("OP_CHECKSIG requiere <sig> <pubKey>");
                byte[] sig = popOrFail("OP_CHECKSIG requiere <sig> <pubKey>");
                boolean ok = crypto.checkSig(sig, pubKey);
                stack.push(boolBytes(ok));
                break;
            }

            default:
                throw new ScriptException("Opcode no implementado: " + op);
        }
    }

    // ----------------- Helpers de pila y tipos -----------------

    private void pushInt(int n) {
        // Simple fase 1: un byte (1..16)
        stack.push(new byte[]{(byte) n});
    }

    private byte[] popOrFail(String msg) {
        byte[] v = stack.poll();
        if (v == null) throw new ScriptException("Stack underflow: " + msg);
        return v;
    }

    private boolean asBool(byte[] v) {
        // false si está vacío o todos sus bytes son 0
        if (v.length == 0) return false;
        for (byte b : v) {
            if (b != 0) return true;
        }
        return false;
    }

    private byte[] boolBytes(boolean b) {
        return new byte[]{(byte) (b ? 1 : 0)};
    }

    // ----------------- Trace / impresión -----------------

    private String stackToString() {
        List<byte[]> list = new ArrayList<byte[]>(stack); // top -> bottom en ArrayDeque iterando
        StringBuilder sb = new StringBuilder();
        sb.append("[TOP ");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(pretty(list.get(i)));
        }
        sb.append("]");
        return sb.toString();
    }

    private String pretty(byte[] v) {
        String s = new String(v, StandardCharsets.UTF_8);
        boolean printable = true;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!(c == 9 || c == 10 || c == 13 || (c >= 32 && c <= 126))) {
                printable = false;
                break;
            }
        }
        if (printable) return "\"" + s + "\"";
        return "0x" + toHex(v);
    }

    private String toHex(byte[] v) {
        StringBuilder sb = new StringBuilder();
        for (byte b : v) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ----------------- PARSER SIMPLE (tokens por espacios) -----------------

    /**
     * Parser simple:
     * - Tokens separados por espacios.
     * - PUSHDATA <dato> empuja el dato.
     * - Si <dato> empieza con 0x..., se interpreta como bytes hex (para pubKeyHash).
     * - Si token coincide con un Opcode, se agrega como instrucción.
     * - Si no coincide, se trata como dato (push).
     */
    public static List<Instruction> parse(String script) {
        List<Instruction> program = new ArrayList<Instruction>();

        if (script == null) return program;
        script = script.trim();
        if (script.isEmpty()) return program;

        String[] tokens = script.split("\\s+");

        for (int i = 0; i < tokens.length; i++) {
            String t = tokens[i];

            // PUSHDATA <token>
            if ("PUSHDATA".equalsIgnoreCase(t)) {
                if (i + 1 >= tokens.length) {
                    throw new ScriptException("PUSHDATA necesita un dato después");
                }
                String dataToken = tokens[++i];

                // Soporte hex: PUSHDATA 0xAABBCC...
                if (dataToken.startsWith("0x") || dataToken.startsWith("0X")) {
                    program.add(Instruction.push(hexToBytes(dataToken.substring(2))));
                } else {
                    program.add(Instruction.push(dataToken.getBytes(StandardCharsets.UTF_8)));
                }
                continue;
            }

            // Si el token es un opcode
            try {
                Opcode op = Opcode.valueOf(t);
                program.add(Instruction.op(op));
                continue;
            } catch (IllegalArgumentException ignored) {
                // cae al fallback
            }

            // Fallback: tratar token como dato (push)
            if (t.startsWith("0x") || t.startsWith("0X")) {
                program.add(Instruction.push(hexToBytes(t.substring(2))));
            } else {
                program.add(Instruction.push(t.getBytes(StandardCharsets.UTF_8)));
            }
        }

        return program;
    }

    private static byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0) {
            throw new ScriptException("Hex inválido: longitud impar");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new ScriptException("Hex inválido");
            out[i] = (byte) ((hi << 4) + lo);
        }
        return out;
    }
}