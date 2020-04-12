package deaddrop_prototype;

import java.io.Console;
import java.util.Scanner;

public class PasswordUtils {
//helper class as given by niels, will probably be removed
    // This utility tries to use Console.readPassword()
    // which hides the password typed by the user (because echoing is disabled).
    // Since users of IntelliJ may not connect to the Console,
    // the utility provides an alternative (which however does not disable echoing).

    public static char[] getUserPassword() {
        char[] password = {};
        System.out.print("Please enter password:");
        Console console = System.console();
        if (console != null) {
            password = console.readPassword();
            System.out.println("Password: " + new String(password));
            // delete above println() after testing
        } else {
            Scanner scanner = new Scanner(System.in);
            String s = scanner.nextLine();
            password = s.toCharArray();
        }
        return password;
    }
}
