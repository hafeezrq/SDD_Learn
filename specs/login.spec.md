## Behavior Rule

RULE 1: Successful Authentication

IF:

- email exists
- password matches

THEN:

- return 200
- return session_token

RULE 2: Invalid Credentials

IF:

- email does not exist OR
- password is incorrect

THEN:

- return 401
- return error "invalid_credentials"

  CONSTRAINT:

- response must not reveal whether the email exists

RULE 3: Invalid Input

IF:

- email is not a valid format OR
- password is missing OR
- password length < 8

THEN:

- return 400
- return error "invalid_input"

RULE 4: Email Normalization

IF:

- email contains leading/trailing spaces OR
- email has uppercase letters

THEN:

- system must:
  - trim whitespace
  - convert to lowercase

AND:

- authentication must use the normalized email

RULE 5: Timing Consistency

IF:

- login request is processed

THEN:

- response time must not significantly differ between:
  - valid email
  - non-existent email

AND:

- password comparison must always execute
  even if the email does not exist

RULE 6: Session Token Generation

IF:

- authentication succeeds

THEN:

- system must generate a session_token

CONSTRAINTS:

- token must be cryptographically random
- token length must be at least 32 bytes (after encoding)
- each token must be unique

RULE 7: Session Storage

IF:

- authentication succeeds

THEN:

- store session_token with:
  - associated user (email)
  - expiration timestamp

---

RULE 8: Session Expiration

IF:

- session_token is used after expiration

THEN:

- reject request with 401
- return error "session_expired"

RULE 9: Logout

IF:

- a valid session_token is provided

THEN:

- invalidate the session (remove from store)
- return 200

---

RULE 10: Post-Logout Behavior

IF:

- a session_token has been logged out

THEN:

- any further use must return:
  - 401
  - error "invalid_token"

RULE 11: User Lookup

IF:

- email is provided

THEN:

- system must look up user in data store

---

RULE 12: Multiple Users

IF:

- multiple users exist

THEN:

- authentication must work independently for each user

---

CONSTRAINT:

- user lookup must not break timing consistency invariant

RULE 13: User Registration

IF:

- email and password are valid
- email does not already exist

THEN:

- create new user
- store password securely (hashed)
- return 201

---

RULE 14: Duplicate Email

IF:

- email already exists

THEN:

- return 409
- error "email_exists"

---

RULE 15: Registration Validation

IF:

- input is invalid

THEN:

- return 400
- error "invalid_input"

RULE 16: Password Hashing

IF:

- password is stored

THEN:

- it must be hashed using a slow, salted algorithm

CONSTRAINTS:

- hashing must be resistant to brute-force attacks
- plain-text passwords must never be stored
