# Indramala Yoga Sansthan — Security Improvement Report

## Severity Ratings

| Rating | Meaning |
|--------|---------|
| **CRITICAL** | Actively exploitable, can lead to full compromise or data breach |
| **HIGH** | Serious vulnerability, likely exploitable with moderate effort |
| **MEDIUM** | Exploitable under certain conditions or with limited impact |
| **LOW** | Minor issue, defense-in-depth hardening |

---

## Table of Contents

1. [Authentication & Password Security](#1-authentication--password-security)
2. [Authorization & Access Control](#2-authorization--access-control)
3. [Session Management](#3-session-management)
4. [Cross-Site Scripting (XSS)](#4-cross-site-scripting-xss)
5. [Cross-Site Request Forgery (CSRF)](#5-cross-site-request-forgery-csrf)
6. [Secrets & Credential Management](#6-secrets--credential-management)
7. [Payment Security](#7-payment-security)
8. [Input Validation & Data Integrity](#8-input-validation--data-integrity)
9. [HTTP Security Headers](#9-http-security-headers)
10. [Error Handling & Information Disclosure](#10-error-handling--information-disclosure)
11. [Database Security](#11-database-security)
12. [Dependency & Supply Chain Security](#12-dependency--supply-chain-security)
13. [Denial of Service (DoS)](#13-denial-of-service-dos)
14. [Logging & Monitoring](#14-logging--monitoring)
15. [Prioritized Remediation Plan](#15-prioritized-remediation-plan)

---

## 1. Authentication & Password Security

### 1.1 Plaintext Password Storage for Users — CRITICAL

**File:** `app.js`, `/register` route (line ~213)

```js
db.prepare(`
  INSERT INTO users (name, lastname, Ph_no, gender, password)
  VALUES (?, ?, ?, ?, ?)
`).run(firstName, secondName, phoneNo, Gender, password);
```

User passwords are stored **in plaintext**. Anyone with database access (backup leak, SQLi, insider) can read every user's password.

**Fix:** Hash with bcrypt before storing, just as the `/apply` route already does for instructors:
```js
const hashedPassword = bcrypt.hashSync(password, 10);
db.prepare(`...`).run(firstName, secondName, phoneNo, Gender, hashedPassword);
```

### 1.2 Login Does Not Verify Passwords — CRITICAL

**File:** `app.js`, `/login` route (line ~234)

```js
const user = db.prepare('SELECT * FROM users WHERE Ph_no = ?').get(phoneNo);
if (user) {
  // Logs in immediately — password is NEVER checked
  req.session.user_type = 'user';
  ...
}
```

The login route only checks if the phone number exists. **Any phone number in the database can be accessed with any password** (or no password at all). The same applies to instructor login.

**Fix:**
```js
const user = db.prepare('SELECT * FROM users WHERE Ph_no = ?').get(phoneNo);
if (user && bcrypt.compareSync(password, user.password)) {
  // Now authenticated
}
```

### 1.3 Hardcoded Admin Credentials — CRITICAL

**File:** `app.js`, `/login` route (line ~230)

```js
if (phoneNo === '9999999999' && password === 'yogaws') {
  req.session.user_type = 'admin';
  return res.redirect('/admin');
}
```

Admin credentials are hardcoded in source code. Anyone reading the repo has full admin access.

**Fix:**
use environment variables: `process.env.ADMIN_PHONE`, `process.env.ADMIN_PASSWORD_HASH`.


### 1.4 No Password Strength Enforcement (Server-Side)

The registration form has client-side `minlength="8"`, but the server does not validate password length or complexity. An attacker can bypass the form and POST directly.

**Fix:** Validate server-side:
```js
if (!password || password.length < 8) {
  req.flash('error', 'Password must be at least 8 characters');
  return res.redirect('/');
}
```

### 1.5 No Rate Limiting on Login

There is no brute-force protection. An attacker can try unlimited phone/password combinations.

**Fix:** Use `express-rate-limit`:
```js
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, please try again later.'
});
app.post('/login', loginLimiter, (req, res) => { ... });
```

### 1.6 No Account Lockout Mechanism

Even with rate limiting, there's no per-account lockout after N failed attempts.

**Fix:** Track failed attempts per phone number in the database. Lock the account after 5 failed attempts for 15 minutes. don't let the account log in for next 15 minutes

### 1.7 Confirm-Password Not Validated Server-Side

The registration form sends `confirmpassword`, but the server never checks `password === confirmpassword`.

**Fix:** Add server-side validation before inserting into the database.

---

## 2. Authorization & Access Control

### 2.1 Admin Routes Have No Auth Checks — CRITICAL

**File:** `app.js` — Multiple routes

The following admin routes have **no authentication or authorization check**:

| Route | Issue |
|-------|-------|
| `GET /edit_enrollments` | Anyone can view all enrollments |
| `POST /delete_enrollment/:appid` | Anyone can delete any enrollment + user |
| `GET /edit_instructors` | Anyone can view all instructor data (phone, address) |
| `POST /add_instructor_course/:tid` | Anyone can assign courses to instructors |
| `POST /remove_instructor_course/:tid/:cid` | Anyone can remove instructor courses |
| `POST /delete_instructor_enrollment/:tid` | Anyone can delete any instructor |
| `GET /edit_course` | Anyone can view course management |
| `POST /edit_course` | Anyone can add/modify courses |
| `POST /delete_course/:course_id` | Anyone can delete any course |

Only `/admin` checks `req.session.user_type === 'admin'`. Every other admin action is completely unprotected.

**Fix:** Create an admin middleware and apply it to all administrative routes:
```js
function requireAdmin(req, res, next) {
  if (!req.session.user_type || req.session.user_type !== 'admin') {
    req.flash('warning', 'Unauthorized access.');
    return res.redirect('/login');
  }
  next();
}

app.get('/edit_enrollments', requireAdmin, (req, res) => { ... });
app.post('/delete_enrollment/:appid', requireAdmin, (req, res) => { ... });
// ... apply to all admin routes
```

### 2.2 `/teachercart` Accessible Without Login

**File:** `app.js`, line ~197

```js
app.get('/teachercart', (req, res) => {
  res.render('teachercart');
});
```

This route renders the teacher cart page for anyone, regardless of login status.

**Fix:** Require instructor session or remove this standalone route (the `/enroll` route already handles the dispatch).

### 2.3 `/pay` Page Accessible Without Login or Order

**File:** `app.js`, `/pay` route

The pay page renders even if `order_id`, `courses`, or `amount` are undefined. This exposes the Razorpay integration to anyone.

**Fix:** Check for valid session data before rendering:
```js
app.get('/pay', (req, res) => {
  if (!req.session.user_id || !req.session.order_id) {
    return res.redirect('/login');
  }
  // ... render
});
```

### 2.4 `/process_payment` Has No Authentication

Anyone can POST to `/process_payment` with any username and course list to fraudulently enroll users in courses without payment.

**Fix:** Require a valid session AND verify the Razorpay payment signature before inserting enrollment records. See Section 7.

---

## 3. Session Management

### 3.1 Weak Session Secret — HIGH

**File:** `app.js`, line ~27

```js
app.use(session({
  secret: 'indramalayoga',
  ...
}));
```

The session secret is a simple, guessable string hardcoded in source. If leaked, an attacker can forge session cookies.

**Fix:**
- Use a cryptographically random secret: `require('crypto').randomBytes(64).toString('hex')`
- Store it in an environment variable: `process.env.SESSION_SECRET`

### 3.2 No `httpOnly` or `secure` Cookie Flags

The session cookie configuration doesn't explicitly set `httpOnly: true` (though express-session defaults to this) or `secure: true`.

**Fix:**
```js
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));
```

### 3.3 No Session Regeneration After Login

After successful login, the same session ID is reused. This enables session fixation attacks.

**Fix:**
```js
req.session.regenerate((err) => {
  if (err) { ... }
  req.session.user_type = 'user';
  req.session.user_id = user.UID;
  // ... set session data then save
  req.session.save(() => res.redirect('/success'));
});
```

### 3.4 In-Memory Session Store

The default `MemoryStore` is used. This leaks memory over time and loses all sessions on restart. In production, sessions should persist.

**Fix:** Use the production-ready store `connect-sqlite3`.

---

## 4. Cross-Site Scripting (XSS)

### 4.1 Unescaped Output in `pay.ejs` — HIGH

**File:** `views/pay.ejs`

```ejs
"prefill": {
    "name": "<%- full_username %>",
    ...
}
...
username: '<%- full_username %>',
courses: <%- JSON.stringify(courses) %>
```

The `<%-` tag outputs **unescaped HTML**. If `full_username` contains `'; alert('xss'); //` or similar, it will execute as JavaScript. The same applies to course names injected via `JSON.stringify` inside inline script.

**Fix:**
- Use `<%= %>` (escaped) for HTML contexts.
- For JavaScript contexts, serialize values safely:
```ejs
<script>
  var fullUsername = <%- JSON.stringify(full_username) %>;
  var courses = <%- JSON.stringify(courses) %>;
</script>
```
Using `JSON.stringify` is safe for JS contexts because it produces valid JSON, but ensure you do NOT wrap it in extra quotes.

### 4.2 `innerHTML` Used for Cart Display — MEDIUM

**File:** `views/addtocart.ejs` (inline script)

```js
document.getElementById("cartItem").innerHTML = cart.map((item) => {
    return (`<div class='cart-item'>
        ...
        <p style='font-size:12px;'>${item.title} ...
    `);
}).join('');
```

If `item.title` or `item.image` were ever sourced from user or server input, this would be a DOM-XSS vector. Currently the data is client-side-only, but this is fragile.

**Fix:** Use `textContent` for text nodes, or sanitize before inserting HTML. Better: use DOM creation APIs.

### 4.3 Flash Messages May Contain User Input

Error flash messages include raw error strings:
```js
req.flash('error', 'Registration failed: ' + err.message);
```

If `err.message` contains HTML and the flash template uses `<%-`, this is XSS. The current templates use `<%= %>` for flash messages (safe), but this should be enforced consistently.

**Fix:** Always use `<%= %>` for flash messages. Never use `<%- %>`.

---

## 5. Cross-Site Request Forgery (CSRF)

### 5.1 No CSRF Protection on Any Form — HIGH

No form in the application includes a CSRF token. All POST endpoints (registration, login, enrollment deletion, course management, payment) are vulnerable to CSRF attacks.

An attacker could create a page that auto-submits a form to `/delete_enrollment/1` or `/delete_course/1` when an admin visits it.

**Fix:** Use the `csurf` middleware (or `csrf-csrf` for modern Express):
```js
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: false }); // use session-based

// Apply to all routes that render forms:
app.get('/login', csrfProtection, (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() });
});

// Validate on POST:
app.post('/login', csrfProtection, (req, res) => { ... });
```

In templates:
```html
<input type="hidden" name="_csrf" value="<%= csrfToken %>">
```

For AJAX endpoints (`/create_order`, `/process_payment`), include the token in a request header.

---

## 6. Secrets & Credential Management

### 6.1 Razorpay Secret Key in Source Code — CRITICAL

**File:** `app.js`, line ~46

```js
const razorpayClient = new Razorpay({
  key_id: 'rzp_test_EJa6zI3VKH91qU',
  key_secret: 'aBL7GC5PGWoHSTQJuyu6bfGa'
});
```

The Razorpay **secret key** is committed to source code. This is the private key used to create orders and verify payments. If this repo is public or leaked, an attacker can:
- Create fraudulent orders
- Refund payments
- Access payment data via Razorpay API

**Fix:**
```js
const razorpayClient = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});
```

Use a `.env` file (with `dotenv`) for local development and ensure `.env` is in `.gitignore`.

### 6.2 Razorpay Key ID Exposed in Client-Side HTML — MEDIUM

**File:** `views/pay.ejs`

```js
"key": "rzp_test_EJa6zI3VKH91qU",
```

The key ID (not the secret) is in the client-side JavaScript. This is necessary for Razorpay checkout but should be the **publishable key only** and should be passed as a template variable from the server (sourced from env vars), not hardcoded.

**Fix:** Pass `razorpayKeyId` from the server:
```js
res.render('pay', { razorpayKeyId: process.env.RAZORPAY_KEY_ID, ... });
```

### 6.3 No `.env` File or Environment Variable Usage

The application has zero use of environment variables. All configuration (session secret, DB path, Razorpay keys, admin credentials, port) is hardcoded.

**Fix:**
- Install `dotenv`: `npm install dotenv`
- Create `.env` with all secrets
- Add `.env` to `.gitignore`
- Load at startup: `require('dotenv').config()`

### 6.4 No `.gitignore` File Observed

There's no `.gitignore` in the workspace. The database file (`../instances/YWS.db`), any `.env` files, and `node_modules` may all be committed to version control.

**Fix:** Create a `.gitignore`:
```
node_modules/
.env
*.db
```

---

## 7. Payment Security

### 7.1 No Razorpay Payment Signature Verification — CRITICAL

**File:** `app.js`, `/process_payment` route

After Razorpay processes a payment, the client-side handler calls `/process_payment` with just a username and course list. The server **never verifies** the Razorpay payment signature (`razorpay_signature`).

This means:
1. Anyone can call `/process_payment` directly (no auth check) with any username + courses.
2. Even a failed/cancelled payment could result in enrollment if the client JS is modified.
3. There is no proof of payment stored.

**Fix:** Verify the payment signature server-side using Razorpay's utility:
```js
const crypto = require('crypto');

app.post('/process_payment', (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

  const body = razorpay_order_id + '|' + razorpay_payment_id;
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(body)
    .digest('hex');

  if (expected !== razorpay_signature) {
    return res.json({ success: false, error: 'Payment verification failed' });
  }

  // Now safe to enroll the user
  // Use session data (not request body) for username/courses
});
```

### 7.2 Client Controls the Payment Amount — HIGH

**File:** `app.js`, `/create_order`

```js
const { amount, courses = [] } = req.body;
```

The payment amount comes directly from the client-side JavaScript. An attacker can modify the amount to `100` (₹1) and still enroll in courses worth thousands.

**Fix:** Calculate the amount server-side based on the selected courses and their database prices:
```js
let serverAmount = 0;
for (const courseName of courses) {
  const course = db.prepare('SELECT Price FROM course WHERE Course_name = ?').get(courseName);
  if (course) serverAmount += course.Price;
}
// Use serverAmount * 100 for Razorpay
```

### 7.3 Static Order Receipt ID

```js
receipt: 'order_rcptid_11',
```

Every order uses the same receipt ID. This makes it impossible to track or audit orders.

**Fix:** Generate unique receipt IDs:
```js
receipt: `order_${Date.now()}_${req.session.user_id}`,
```

---

## 8. Input Validation & Data Integrity

### 8.1 No Server-Side Input Validation on Any Route — HIGH

None of the POST routes validate input types, lengths, or formats. Examples:

| Route | Field | Issue |
|-------|-------|-------|
| `/register` | `phoneNo` | No check for 10-digit number |
| `/register` | `firstName` | No length limit, could be 10MB |
| `/workshop` | `ph_no` | No format validation |
| `/apply` | `dob-date`, `dob-month`, `dob-year` | No range validation (month=99, day=50) |
| `/apply` | `postal` | No format check |
| `/edit_course` | `price` | No check for negative numbers |
| `/create_order` | `amount` | No check that it's positive |

**Fix:** Validate all inputs server-side. Use a library like `express-validator` or `joi`:
```js
const { body, validationResult } = require('express-validator');

app.post('/register', [
  body('phoneNo').matches(/^[0-9]{10}$/),
  body('firstName').trim().isLength({ min: 1, max: 100 }),
  body('password').isLength({ min: 8, max: 100 }),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { ... }
});
```

### 8.2 `parseInt` Without Validation on Route Params

Multiple routes use `parseInt(req.params.appid)` etc. without checking the result. If `NaN`, the DB query may behave unexpectedly.

**Fix:** Validate that parsed integers are finite and positive:
```js
const appid = parseInt(req.params.appid);
if (!Number.isFinite(appid) || appid <= 0) {
  return res.status(400).send('Invalid ID');
}
```

### 8.3 User Lookup by Concatenated Name — MEDIUM

**File:** `app.js`, `/process_payment`

```js
const user = db.prepare("SELECT UID FROM users WHERE name || ' ' || lastname = ?").get(username);
```

Looking up users by concatenated name is unreliable (names aren't unique) and attacker-controllable. A user named "Admin Panel" could match someone else.

**Fix:** Look up by `user_id` from the session, not by a name sent from the client:
```js
const user_id = req.session.user_id;
```

---

## 9. HTTP Security Headers

### 9.1 No Security Headers Set — MEDIUM

The application sets no HTTP security headers. This leaves it vulnerable to clickjacking, MIME sniffing, and other browser-level attacks.

**Fix:** Use the `helmet` middleware:
```bash
npm install helmet
```
```js
const helmet = require('helmet');
app.use(helmet());
```

This automatically sets:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN` (prevents clickjacking)
- `Strict-Transport-Security` (forces HTTPS)
- `X-XSS-Protection` (legacy browsers)
- `Content-Security-Policy` (restrict resource origins)
- `Referrer-Policy`

### 9.2 PDF iframes Susceptible to Clickjacking

`brochure.ejs`, `certificates.ejs`, `Syllabus.ejs` are full-page iframes with no `X-Frame-Options` protection on the app itself. While these pages frame internal PDFs, without `X-Frame-Options`, the entire site can be framed by a malicious page.

**Fix:** `helmet()` handles this. For the PDFs, ensure they're served with appropriate headers.

---

## 10. Error Handling & Information Disclosure

### 10.1 Database Error Messages Leaked to Users — MEDIUM

Multiple routes flash raw SQLite error messages:
```js
req.flash('error', 'Registration failed: ' + err.message);
req.flash('error', err.message);
```

These can reveal database schema, table names, and column names to end users.

**Fix:** Log the full error server-side, but show a generic message to users:
```js
console.error('Registration error:', err);
req.flash('error', 'Registration failed. Please try again.');
```

### 10.2 No Global Error Handler

There's no Express error-handling middleware. Unhandled errors will show the default Express error page with a stack trace in development.

**Fix:**
```js
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', { message: 'Something went wrong.' });
});
```

### 10.3 JSON API Errors Leak Internal Details

```js
return res.json({ success: false, error: err.message });
```

API endpoints (`/create_order`, `/process_payment`) return raw error messages in JSON.

**Fix:** Return generic error messages in production:
```js
return res.json({ success: false, error: 'An error occurred. Please try again.' });
```

---

## 11. Database Security

### 11.1 Database File Outside Application Root

```js
return new Database(path.join(__dirname, '..', 'instances', 'YWS.db'));
```

The database is stored in `../instances/`, outside the application directory. This could be inadvertently served by misconfigured hosting or accessible via path traversal.

**Fix:** Move the database inside the application directory (but outside the static folder), or ensure the parent directory is properly secured.

### 11.2 New Database Connection Per Request

Every request creates a new `Database` connection and manually closes it. If an error occurs on an unexpected code path, the connection may leak.

**Fix:** Use a single database connection (better-sqlite3 is synchronous and safe for this), or use a connection pool:
```js
const db = new Database(path.join(__dirname, '..', 'instances', 'YWS.db'));
// Reuse `db` across all routes — no need to open/close per request
```

### 11.3 `SELECT *` Fetches Excessive Data

```js
const user = db.prepare('SELECT * FROM users WHERE Ph_no = ?').get(phoneNo);
const instructor = db.prepare('SELECT * FROM instructors WHERE Ph_no = ?').get(phoneNo);
```

This fetches all columns including password hashes, which are then available in memory and potentially logged.

**Fix:** Select only needed columns:
```js
const user = db.prepare('SELECT UID, name, lastname, Ph_no, password FROM users WHERE Ph_no = ?').get(phoneNo);
```

### 11.4 No Database Encryption

The SQLite database is stored as a plain file with no encryption. If the server is compromised, all data is immediately readable.

**Fix:** For sensitive data, consider `better-sqlite3` with SQLCipher extension, or encrypt sensitive columns individually.

---

## 12. Denial of Service (DoS)

### 12.1 No Request Body Size Limit

```js
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
```

No `limit` option is set. An attacker can send multi-GB request bodies and exhaust server memory.

**Fix:**
```js
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));
```

### 12.2 No Rate Limiting on Any Endpoint

No rate limiting exists on any route. An attacker can:
- Flood `/workshop` to fill the database with fake registrations
- Flood `/register` to create thousands of accounts
- Flood `/create_order` to create Razorpay orders

**Fix:** Apply `express-rate-limit` globally with stricter limits on sensitive endpoints:
```js
const rateLimit = require('express-rate-limit');
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
```

### 12.3 Synchronous bcrypt in Request Handler

```js
const hashedPassword = bcrypt.hashSync(password, 10);
```

`bcryptjs` synchronous operations block the event loop. Under load, this will stall all other requests.

**Fix:** Use the async version:
```js
const hashedPassword = await bcrypt.hash(password, 10);
```

