# Secure Login System 

A command-line Java authentication project demonstrating password hashing, input validation, SQLite persistence, protected profile output, and temporary lockout after repeated failed logins.

## Features

- User registration with username and password validation
- BCrypt password hashing with work factor 12; BCrypt generates a unique salt for each password
- Password hashes only are stored in SQLite; plaintext passwords are not stored
- Login verifies a submitted password against the stored BCrypt hash
- Protected profile details are shown only after successful authentication
- Account is temporarily locked for 60 seconds after five failed password attempts
- Prepared statements are used for database operations
- Generic invalid-credential message helps avoid revealing whether a username exists

## Technology stack

- Java 17+
- Maven
- SQLite
- Spring Security Crypto (`BCryptPasswordEncoder`)

## Project structure

```text
Secure-Login-System/
├── pom.xml
├── README.md
├── .gitignore
└── src/
    └── main/
        └── java/
            └── com/
                └── thanuja/
                    └── securelogin/
                        ├── Main.java
                        ├── AuthService.java
                        └── UserRepository.java
```

## Run the project

1. Install JDK 17 or newer and Maven.
2. Open a terminal in the project folder.
3. Run:

   ```bash
   mvn clean compile exec:java
   ```

The first run downloads dependencies and creates `secure-login.db` in the current working directory.

## Test checklist

1. Choose **Register** and create a username such as `thanuja01`.
2. Use a password with uppercase, lowercase, a number, and a symbol, for example `Thanuja@123`.
3. Choose **Login** and enter the correct credentials. Confirm that the protected profile is displayed.
4. Try an incorrect password. Confirm that login is rejected.
5. Enter an incorrect password five times. Confirm the 60-second lockout.
6. Exit and restart the program; confirm the account and lockout data persist in SQLite.

Take your own screenshots of successful login, invalid-password rejection, and account lockout for submission.

## Security design

### Password storage and salting

Passwords are hashed with BCrypt using `BCryptPasswordEncoder(12)`. BCrypt includes a random salt in the encoded hash and stores the salt and work-factor metadata with it. During login, `matches()` verifies the candidate password against the saved hash. The application never needs to decrypt a password and does not store plaintext passwords.

### Input validation

Usernames are restricted to 3-30 letters, digits, dots, underscores, or hyphens. Passwords must be 8-72 characters and include uppercase and lowercase letters, a number, and a symbol. The 72-character maximum avoids BCrypt's input-length truncation behavior.

### Login lockout

Five consecutive failed password attempts trigger a 60-second lockout. A successful login resets the failed-attempt counter. This is a simple educational demonstration; a production system should also use rate limiting by IP/device, monitoring, progressive delays, and careful recovery workflows.

### Protected view

The profile information is printed only after the authentication service returns a successful login result. The menu and login prompts are public; the profile output is the authenticated view.

### Database safety

Database values are passed through JDBC prepared statements. The local database file is excluded from Git using `.gitignore`.

## Important limitations

This is a learning/demo console application, not a production web authentication service. It does not implement browser sessions, HTTPS, CSRF protection, email verification, password reset, multi-factor authentication, or distributed rate limiting. Do not use it as-is to protect real accounts or sensitive information.
