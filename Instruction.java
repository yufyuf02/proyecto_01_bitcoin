public class Instruction {

    private final Opcode opcode;
    private final byte[] data;

    private Instruction(Opcode opcode, byte[] data) {
        this.opcode = opcode;
        this.data = data;
    }

    public static Instruction op(Opcode opcode) {
        return new Instruction(opcode, null);
    }

    public static Instruction push(byte[] data) {
        return new Instruction(Opcode.PUSHDATA, data);
    }

    public Opcode getOpcode() {
        return opcode;
    }

    public byte[] getData() {
        return data;
    }
}