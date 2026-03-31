/** Excepción lanzada cuando una instrucción falla durante la ejecución del script. */
public class ScriptException extends RuntimeException {

    public ScriptException(String message) {
        super(message);
    }
}
