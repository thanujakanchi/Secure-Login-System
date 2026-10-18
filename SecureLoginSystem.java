import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class SecureLoginSystem {

    private static final Path DB = Paths.get("secure-users.db");
    private static final Scanner IN = new Scanner(System.in);
    private static final SecureRandom RNG = new SecureRandom();

    private static final int ITERATIONS = 210000;
    private static final int SALT_SIZE = 16;
    private static final int HASH_BITS = 256;
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCK_MILLIS = 60000;

    private static final Map<String, User> USERS =
            new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private static class User {
        String username;
        String salt;
        String hash;
        int failures;
        long lockedUntil;

        User(String username, String salt, String hash,
             int failures, long lockedUntil) {
            this.username = username;
            this.salt = salt;
            this.hash = hash;
            this.failures = failures;
            this.lockedUntil = lockedUntil;
        }
    }

    public static void main(String[] args) {
        try {
            loadUsers();
        } catch (Exception e) {
            System.out.println("Could not load database: " + e.getMessage());
            return;
        }

        System.out.println("================================");
        System.out.println("       SECURE LOGIN SYSTEM");
        System.out.println("================================");

        while (true) {
            System.out.println("\n1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose option: ");

            String choice = IN.nextLine().trim();

            try {
                switch (choice) {
                    case "1":
                        register();
                        break;
                    case "2":
                        login();
                        break;
                    case "3":
                        System.out.println("Application closed.");
                        return;
                    default:
                        System.out.println("Invalid option.");
                }
            } catch (Exception e) {
                System.out.println("Operation failed: " + e.getMessage());
            }
        }
    }

    private static void register() throws Exception {
        System.out.println("\n--- Registration ---");
        System.out.print("Enter username: ");

        String username = IN.nextLine().trim();

        if (!username.matches("[A-Za-z0-9_.-]{3,30}")) {
            System.out.println(
                "Username must be 3-30 characters: letters, numbers, . _ -"
            );
            return;
        }

        if (USERS.containsKey(username)) {
            System.out.println("Username already exists.");
            return;
        }

        char[] password = readPassword("Create password: ");

        if (!strongPassword(password)) {
            Arrays.fill(password, '\0');
            System.out.println(
                "Use 8-128 characters with uppercase, lowercase, "
                + "a number, and a symbol."
            );
            return;
        }

        char[] confirmation = readPassword("Confirm password: ");

        if (!Arrays.equals(password, confirmation)) {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
            System.out.println("Passwords do not match.");
            return;
        }

        Arrays.fill(confirmation, '\0');

        byte[] salt = new byte[SALT_SIZE];
        RNG.nextBytes(salt);

        byte[] passwordHash;
        try {
            passwordHash = hashPassword(password, salt);
        } finally {
            Arrays.fill(password, '\0');
        }

        User user = new User(
            username,
            Base64.getEncoder().encodeToString(salt),
            Base64.getEncoder().encodeToString(passwordHash),
            0,
            0L
        );

        USERS.put(username, user);

        if (saveUsers()) {
            System.out.println("Registration successful!");
            System.out.println("You can now log in.");
        } else {
            USERS.remove(username);
            System.out.println("Could not save account to database.");
        }
    }

    private static void login() throws Exception {
        System.out.println("\n--- Login ---");
        System.out.print("Enter username: ");

        String username = IN.nextLine().trim();
        User user = USERS.get(username);

        if (user != null && user.lockedUntil > System.currentTimeMillis()) {
            long seconds =
                (user.lockedUntil - System.currentTimeMillis() + 999) / 1000;

            System.out.println(
                "Account locked. Try again in " + seconds + " seconds."
            );
            return;
        }

        if (user != null && user.lockedUntil != 0) {
            user.lockedUntil = 0;
            user.failures = 0;
        }

        char[] password = readPassword("Enter password: ");

        byte[] salt;
        byte[] expectedHash;

        if (user == null) {
            salt = new byte[SALT_SIZE];
            expectedHash = new byte[HASH_BITS / 8];
        } else {
            salt = Base64.getDecoder().decode(user.salt);
            expectedHash = Base64.getDecoder().decode(user.hash);
        }

        byte[] actualHash;
        try {
            actualHash = hashPassword(password, salt);
        } finally {
            Arrays.fill(password, '\0');
        }

        boolean valid = user != null
                && MessageDigest.isEqual(expectedHash, actualHash);

        if (valid) {
            user.failures = 0;
            user.lockedUntil = 0;

            if (!saveUsers()) {
                System.out.println("Warning: account state could not be saved.");
            }

            System.out.println("\nLogin successful!");
            System.out.println("------------------------------");
            System.out.println("Welcome, " + user.username + "!");
            System.out.println("Account status: Authenticated");
            System.out.println("Protected profile accessed.");
            System.out.println("------------------------------");
        } else {
            System.out.println("Invalid username or password.");

            if (user != null) {
                user.failures++;

                if (user.failures >= MAX_ATTEMPTS) {
                    user.failures = 0;
                    user.lockedUntil =
                        System.currentTimeMillis() + LOCK_MILLIS;

                    System.out.println(
                        "Too many failed attempts. Locked for 60 seconds."
                    );
                } else {
                    System.out.println(
                        "Attempts remaining: "
                        + (MAX_ATTEMPTS - user.failures)
                    );
                }

                if (!saveUsers()) {
                    System.out.println("Warning: could not save login state.");
                }
            }
        }
    }

private static char[] readPassword(String prompt) {
    System.out.print(prompt);
    System.out.flush();

    String value = IN.nextLine();
    return value.toCharArray();
}



    private static boolean strongPassword(char[] password) {
        if (password.length < 8 || password.length > 128) {
            return false;
        }

        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean symbol = false;

        for (char c : password) {
            if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else if (!Character.isWhitespace(c)) {
                symbol = true;
            }
        }

        return upper && lower && digit && symbol;
    }

    private static byte[] hashPassword(char[] password, byte[] salt)
            throws Exception {

        PBEKeySpec spec =
            new PBEKeySpec(password, salt, ITERATIONS, HASH_BITS);

        try {
            SecretKeyFactory factory =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void loadUsers() throws IOException {
        if (!Files.exists(DB)) {
            return;
        }

        for (String line : Files.readAllLines(DB, StandardCharsets.UTF_8)) {
            String[] fields = line.split("\\t", -1);

            if (fields.length != 5) {
                continue;
            }

            try {
                String username = new String(
                    Base64.getDecoder().decode(fields[0]),
                    StandardCharsets.UTF_8
                );

                byte[] salt = Base64.getDecoder().decode(fields[1]);
                byte[] hash = Base64.getDecoder().decode(fields[2]);

                if (salt.length != SALT_SIZE
                        || hash.length != HASH_BITS / 8) {
                    continue;
                }

                User user = new User(
                    username,
                    fields[1],
                    fields[2],
                    Integer.parseInt(fields[3]),
                    Long.parseLong(fields[4])
                );

                USERS.put(username, user);
            } catch (IllegalArgumentException e) {
                System.out.println("Skipping an invalid database record.");
            }
        }
    }

    private static boolean saveUsers() {
        List<String> lines = new ArrayList<>();

        for (User user : USERS.values()) {
            String encodedUsername = Base64.getEncoder().encodeToString(
                user.username.getBytes(StandardCharsets.UTF_8)
            );

            lines.add(
                encodedUsername + "\t"
                + user.salt + "\t"
                + user.hash + "\t"
                + user.failures + "\t"
                + user.lockedUntil
            );
        }

        Path temp = DB.resolveSibling("secure-users.db.tmp");

        try {
            Files.write(
                temp,
                lines,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
            );

            try {
                Files.move(
                    temp, DB,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
                );
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(
                    temp, DB,
                    StandardCopyOption.REPLACE_EXISTING
                );
            }

            return true;
        } catch (IOException e) {
            try {
                Files.deleteIfExists(temp);
            } catch (IOException ignored) {
                // Ignore temporary-file cleanup errors.
            }
            return false;
        }
    }
}
