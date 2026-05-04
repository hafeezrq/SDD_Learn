const request = require("supertest");
const app = require("../app");

test("returns token for valid credentials", async () => {
  const res = await request(app).post("/login").send({
    email: "user@example.com",
    password: "correctpassword",
  });

  expect(res.statusCode).toBe(200);
  expect(res.body).toHaveProperty("session_token");
});

test("returns 401 for wrong password", async () => {
  const res = await request(app).post("/login").send({
    email: "user@example.com",
    password: "wrongpassword",
  });

  expect(res.statusCode).toBe(401);
  expect(res.body.error).toBe("invalid_credentials");
});

test("returns 401 for non-existent user", async () => {
  const res = await request(app).post("/login").send({
    email: "nouser@example.com",
    password: "whatever123",
  });

  expect(res.statusCode).toBe(401);
  expect(res.body.error).toBe("invalid_credentials");
});

test("same response for wrong password and non-existent user", async () => {
  const res1 = await request(app).post("/login").send({
    email: "user@example.com",
    password: "wrongpassword",
  });

  const res2 = await request(app).post("/login").send({
    email: "nouser@example.com",
    password: "wrongpassword",
  });

  expect(res1.statusCode).toBe(401);
  expect(res2.statusCode).toBe(401);

  expect(res1.body).toEqual(res2.body);
});

describe("Input Validation", () => {
  test("returns 400 for invalid email format", async () => {
    const res = await request(app).post("/login").send({
      email: "invalid-email",
      password: "password123",
    });

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("invalid_input");
  });

  test("returns 400 for missing password", async () => {
    const res = await request(app).post("/login").send({
      email: "user@example.com",
    });

    expect(res.statusCode).toBe(400);
  });

  test("returns 400 for short password", async () => {
    const res = await request(app).post("/login").send({
      email: "user@example.com",
      password: "123",
    });

    expect(res.statusCode).toBe(400);
  });
});

describe("Email Normalization", () => {
  test("trims email whitespace", async () => {
    const res = await request(app).post("/login").send({
      email: " user@example.com ",
      password: "correctpassword",
    });

    expect(res.statusCode).toBe(200);
  });

  test("email is case-insensitive", async () => {
    const res = await request(app).post("/login").send({
      email: "USER@EXAMPLE.COM",
      password: "correctpassword",
    });

    expect(res.statusCode).toBe(200);
  });
});

describe("Security - Timing Consistency", () => {
  test("response time does not differ significantly", async () => {
    const measure = async (payload) => {
      const start = Date.now();
      await request(app).post("/login").send(payload);
      return Date.now() - start;
    };

    const t1 = await measure({
      email: "user@example.com",
      password: "wrongpassword",
    });

    const t2 = await measure({
      email: "nouser@example.com",
      password: "wrongpassword",
    });

    const diff = Math.abs(t1 - t2);

    expect(diff).toBeLessThan(50); // threshold
  });
});

describe("Session Token", () => {
  test("returns a token of sufficient length", async () => {
    const res = await request(app).post("/login").send({
      email: "user@example.com",
      password: "correctpassword",
    });

    expect(res.body.session_token.length).toBeGreaterThanOrEqual(64);
  });

  test("generates different tokens for multiple logins", async () => {
    const tokens = new Set();

    for (let i = 0; i < 5; i++) {
      const res = await request(app).post("/login").send({
        email: "user@example.com",
        password: "correctpassword",
      });

      tokens.add(res.body.session_token);
    }

    expect(tokens.size).toBe(5);
  });
});

describe("Session Storage", () => {
  test("can access protected route with valid token", async () => {
    const login = await request(app).post("/login").send({
      email: "user@example.com",
      password: "correctpassword",
    });

    const token = login.body.session_token;

    const res = await request(app).get("/profile").set("Authorization", token);

    expect(res.statusCode).toBe(200);
  });

  test("rejects expired token", async () => {
    const login = await request(app).post("/login").send({
      email: "user@example.com",
      password: "correctpassword",
    });

    const token = login.body.session_token;

    // simulate expiration delay
    await new Promise((r) => setTimeout(r, 1100));

    const res = await request(app).get("/profile").set("Authorization", token);

    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("session_expired");
  });
});

describe("Logout", () => {
  test("can logout and invalidate session", async () => {
    const login = await request(app).post("/login").send({
      email: "user@example.com",
      password: "correctpassword",
    });

    const token = login.body.session_token;

    // logout
    const logout = await request(app)
      .post("/logout")
      .set("Authorization", token);

    expect(logout.statusCode).toBe(200);

    // try to use token again
    const res = await request(app).get("/profile").set("Authorization", token);

    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("invalid_token");
  });

  test("logout with missing token returns 401", async () => {
    const res = await request(app).post("/logout");

    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("missing_token");
  });
});

describe("Multiple Users", () => {
  test("different users can login independently", async () => {
    const user1 = await request(app).post("/login").send({
      email: "user1@example.com",
      password: "password123",
    });

    const user2 = await request(app).post("/login").send({
      email: "user2@example.com",
      password: "password456",
    });

    expect(user1.statusCode).toBe(200);
    expect(user2.statusCode).toBe(200);
  });

  test("wrong password for one user does not affect another", async () => {
    const res = await request(app).post("/login").send({
      email: "user1@example.com",
      password: "wrongpassword",
    });

    expect(res.statusCode).toBe(401);
  });
});
