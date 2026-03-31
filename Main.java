import java.util.ArrayList;
import java.util.List;
/** Punto de entrada del intérprete. Parsea los argumentos y ejecuta el script. */
public class Main {

    public static void main(String[] args) {

        boolean trace = false;
        List<String> input = new ArrayList<>();

        for (String a : args) {

            if (a.equals("--trace")) trace = true;
            else input.add(a);
        }

        if (input.size() < 2) {

            System.out.println("Usage:");
            System.out.println("java Main [--trace] \"<scriptSig>\" \"<scriptPubKey>\"");
            return;
        }

        String scriptSig = input.get(0);
        String scriptPubKey = input.get(1);

        List<Instruction> program = new ArrayList<>();

        program.addAll(ScriptInterpreter.parse(scriptSig));
        program.addAll(ScriptInterpreter.parse(scriptPubKey));

        ScriptInterpreter vm =
                new ScriptInterpreter(new MockCryptoProvider());

        vm.setTrace(trace);

        boolean result = vm.execute(program);

        System.out.println(result ? "VALID" : "INVALID");
    }
}