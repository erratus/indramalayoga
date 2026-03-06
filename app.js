require('dotenv').config();

const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const Razorpay = require('razorpay');
const { Pool } = require('pg');
const path = require('path');
const flash = require('connect-flash');
const helmet = require('helmet');
const { default: rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

const app = express();

// Trust the first proxy (Vercel / any reverse proxy) so req.ip and
// X-Forwarded-For are resolved correctly by express-rate-limit.
app.set('trust proxy', 1);

// ─── Security Headers ────────────────────────────────────────────────────────
// contentSecurityPolicy disabled — app uses many inline scripts and external CDNs;
// configure a proper CSP policy before enabling in production.
app.use(helmet({ contentSecurityPolicy: false }));

// ─── View Engine ────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Static Files ────────────────────────────────────────────────────────────
app.use('/static', express.static(path.join(__dirname, 'static')));

// Respond to favicon requests immediately — before session/DB middleware —
// so they never cause a database round-trip and can't trigger a 504.
app.get('/favicon.ico', (req, res) => res.status(204).end());


// ─── Body Parsing (with size limits to prevent DoS) ──────────────────────────
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));

// ─── PostgreSQL Connection Pool (Neon) ───────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL_UNPOOLED,
  // In production (Vercel + Neon) allow SSL without validating the cert chain
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  // Fail fast on cold starts instead of hanging until Vercel kills the function
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 10000,
  max: 5,
});

// ─── Session ─────────────────────────────────────────────────────────────────
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET not set. Sessions will not survive restart.');
}
app.use(session({
  store: new pgSession({
    pool: db,
    tableName: 'session',
    // Table is created via schema.sql — removing createTableIfMissing avoids
    // an extra DDL round-trip to Neon on every Vercel cold start.
  }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

// ─── Flash Messages ──────────────────────────────────────────────────────────
app.use(flash());

// ─── Locals + CSRF Token Generation ─────────────────────────────────────────
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  res.locals.session = req.session;
  res.locals.flash_messages = req.flash();
  next();
});

// ─── CSRF Protection Middleware ───────────────────────────────────────────────
function csrfProtect(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  next();
}
app.use(csrfProtect);

// ─── Razorpay Client (lazy) ───────────────────────────────────────────────────
// Instantiated on first use so a missing key only breaks payment routes,
// not the entire app startup.
let _razorpayClient;
function razorpayClient() {
  if (!_razorpayClient) {
    _razorpayClient = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET
    });
  }
  return _razorpayClient;
}

// ─── Pricing Data (server-authoritative) ─────────────────────────────────────
const PRICING_DATA = {
  'general-yoga': {
    regular:   { monthly: 2500, quarterly: 6000, 'half-yearly': 10000, yearly: 17000 },
    alternate: { monthly: 1500, quarterly: 4000, 'half-yearly':  7500, yearly: 11500 }
  },
  'advanced-yoga': {
    regular:   { monthly: 3500, quarterly: 9000, 'half-yearly': 15000, yearly: 21000 },
    alternate: { monthly: 2500, quarterly: 6000, 'half-yearly': 10000, yearly: 15000 }
  }
};

// ─── Auth Middlewares ─────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (!req.session.user_type || req.session.user_type !== 'admin') {
    req.flash('warning', 'Unauthorized access.');
    return res.redirect('/login');
  }
  next();
}

function requireUser(req, res, next) {
  if (!req.session.user_id) {
    req.flash('warning', 'You need to be logged in to access this page.');
    return res.redirect('/login');
  }
  next();
}

function requireInstructor(req, res, next) {
  if (!req.session.instructor_id) {
    req.flash('warning', 'You need to be logged in as an instructor to access this page.');
    return res.redirect('/login');
  }
  next();
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────
// Custom keyGenerator to handle Vercel's proxy headers (Forwarded / X-Forwarded-For)
// ipKeyGenerator wraps the IP so express-rate-limit handles IPv6 correctly (ERR_ERL_KEY_GEN_IPV6)
function getClientIp(req) {
  // RFC 7239 Forwarded header (used by Vercel)
  const forwarded = req.headers['forwarded'];
  if (forwarded) {
    const match = forwarded.match(/for=["[]?([^\],";\s]+)/i);
    if (match) {
      const ip = match[1].replace(/^::ffff:/, '');
      return ipKeyGenerator(ip);
    }
  }
  // De-facto X-Forwarded-For header
  const xff = req.headers['x-forwarded-for'];
  if (xff) return ipKeyGenerator(xff.split(',')[0].trim());
  return ipKeyGenerator(req.socket?.remoteAddress || req.ip || 'unknown');
}

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, keyGenerator: getClientIp });
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyGenerator: getClientIp,
  message: 'Too many login attempts, please try again later.'
});
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyGenerator: getClientIp,
  message: 'Too many registration attempts, please try again later.'
});
app.use(globalLimiter);

// ─── Account Lockout Tracking (in-memory) ────────────────────────────────────
const failedLoginAttempts = new Map();

function isAccountLocked(phone) {
  const rec = failedLoginAttempts.get(phone);
  if (!rec) return false;
  if (rec.lockedUntil && Date.now() < rec.lockedUntil) return true;
  return false;
}

function recordFailedAttempt(phone) {
  const rec = failedLoginAttempts.get(phone) || { count: 0, lockedUntil: null };
  rec.count++;
  if (rec.count >= 5) {
    rec.lockedUntil = Date.now() + 15 * 60 * 1000;
    rec.count = 0;
  }
  failedLoginAttempts.set(phone, rec);
}

function clearFailedAttempts(phone) {
  failedLoginAttempts.delete(phone);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Home
app.get('/', (req, res) => {
  res.render('index', { courses: [] });
});

// Workshop
app.get('/workshop', (req, res) => {
  const messages = req.flash();
  res.render('workshop', { messages });
});

app.post('/workshop', [
  body('first_name').trim().isLength({ min: 1, max: 100 }),
  body('last_name').trim().isLength({ min: 1, max: 100 }),
  body('ph_no').matches(/^[0-9]{10}$/),
  body('comments').optional().trim().isLength({ max: 500 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', 'Invalid input. Please check your details.');
    return res.redirect('/workshop');
  }
  const { first_name, last_name, ph_no, comments = '' } = req.body;
  try {
    await db.query(
      'INSERT INTO workshop_sign_in (first_name, last_name, ph_no, comments) VALUES ($1, $2, $3, $4)',
      [first_name, last_name, ph_no, comments.slice(0, 500)]
    );
    req.flash('success', 'Registration successful!');
  } catch (err) {
    console.error('Workshop registration error:', err);
    req.flash('error', 'Registration failed. Please try again.');
  }
  res.redirect('/workshop');
});

// Know More / Information
app.get('/knowmore', (req, res) => {
  res.render('information');
});

// Brochure
app.get('/brochure', (req, res) => {
  res.render('brochure');
});

// Certificates
app.get('/certificates', (req, res) => {
  res.render('certificates');
});

// Syllabus
app.get('/Syllabus', (req, res) => {
  res.render('Syllabus');
});

// Know About Courses
app.get('/knowabtcourses', (req, res) => {
  res.render('knowabtcourses');
});

// Know About Courses RYT
app.get('/knowabtcourses_RYT', (req, res) => {
  res.render('knowabtcourses_RYT');
});

// Gallery
app.get('/gallery', (req, res) => {
  res.render('gallery');
});

// Vision & Mission
app.get('/vision', (req, res) => {
  res.render('visionNmission');
});

// Enroll – redirect based on session type
app.get('/enroll', (req, res) => {
  if (req.session.instructor_id) {
    return res.render('teachercart');
  } else if (req.session.user_id) {
    return res.render('addtocart');
  } else {
    return res.redirect('/login');
  }
});

// Create Razorpay Order
app.post('/create_order', requireUser, async (req, res) => {
  const user_name = req.session.user_name || '';
  const user_lastname = req.session.user_lastname || '';
  const user_phone = req.session.user_phone || '';
  const full_username = `${user_name} ${user_lastname}`.trim();

  const { courses = [] } = req.body;

  if (!Array.isArray(courses) || courses.length === 0) {
    return res.json({ success: false, error: 'No courses selected' });
  }

  // Server-side price calculation — clients cannot manipulate the amount
  let serverAmount = 0;
  const courseNames = [];
  for (const item of courses) {
    const { dataType, classFrequency, paymentManner, quantity = 1 } = item;
    if (
      !PRICING_DATA[dataType] ||
      !PRICING_DATA[dataType][classFrequency] ||
      PRICING_DATA[dataType][classFrequency][paymentManner] === undefined
    ) {
      return res.json({ success: false, error: 'Invalid course or pricing option' });
    }
    const qty = Math.max(1, parseInt(quantity) || 1);
    serverAmount += PRICING_DATA[dataType][classFrequency][paymentManner] * qty;
    courseNames.push(item.title);
  }
  const amountInPaise = serverAmount * 100;

  try {
    const order = await razorpayClient().orders.create({
      amount: amountInPaise,
      currency: 'INR',
      receipt: `order_${Date.now()}_${req.session.user_id}`,
      notes: {
        customer_name: full_username,
        customer_phone: user_phone
      }
    });

    req.session.order_id = order.id;
    req.session.courses = courseNames;
    req.session.amount = amountInPaise;

    return res.json({ success: true, order_id: order.id });
  } catch (err) {
    console.error('Order creation error:', err);
    return res.json({ success: false, error: 'An error occurred. Please try again.' });
  }
});

// Pay page
app.get('/pay', requireUser, (req, res) => {
  const order_id = req.session.order_id;
  const courses = req.session.courses || [];
  const amount = req.session.amount;

  if (!order_id || !amount) {
    return res.redirect('/enroll');
  }

  const user_name = req.session.user_name || '';
  const user_lastname = req.session.user_lastname || '';
  const user_phone = req.session.user_phone || '';
  const full_username = `${user_name} ${user_lastname}`.trim();

  res.render('pay', {
    order_id,
    courses,
    amount,
    full_username,
    user_phone,
    user_address_line_1: '',
    user_address_line_2: '',
    razorpayKeyId: process.env.RAZORPAY_KEY_ID
  });
});

// Teacher Cart
app.get('/teachercart', requireInstructor, (req, res) => {
  res.render('teachercart');
});

// Register
app.post('/register', registerLimiter, [
  body('firstName').trim().isLength({ min: 1, max: 100 }),
  body('secondName').trim().isLength({ min: 1, max: 100 }),
  body('phoneNo').matches(/^[0-9]{10}$/),
  body('password').isLength({ min: 8, max: 100 }),
  body('Gender').isIn(['Male', 'Female']),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', 'Invalid input. Please check your details.');
    return res.redirect('/');
  }

  const { firstName, secondName, phoneNo, Gender, password, confirmpassword } = req.body;

  if (password !== confirmpassword) {
    req.flash('error', 'Passwords do not match.');
    return res.redirect('/');
  }

  try {
    const existing = (await db.query('SELECT ph_no FROM users WHERE ph_no = $1', [phoneNo])).rows[0];
    if (existing) {
      req.flash('error', 'Phone number already registered. Please use a different phone number.');
      return res.redirect('/');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      'INSERT INTO users (name, lastname, ph_no, gender, password) VALUES ($1, $2, $3, $4, $5) RETURNING uid',
      [firstName, secondName, phoneNo, Gender, hashedPassword]
    );
    const newUserId = result.rows[0].uid;
    req.session.regenerate((err) => {
      if (err) {
        req.flash('danger', 'Registration succeeded but login failed. Please log in.');
        return res.redirect('/login');
      }
      req.session.user_type = 'user';
      req.session.user_id = newUserId;
      req.session.user_name = firstName;
      req.session.user_lastname = secondName;
      req.session.user_phone = phoneNo;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.save(() => res.redirect('/success'));
    });
  } catch (err) {
    console.error('Registration error:', err);
    req.flash('error', 'Registration failed. Please try again.');
    return res.redirect('/');
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', loginLimiter, async (req, res) => {
  const { phoneNo, password } = req.body;

  if (!phoneNo || !password) {
    req.flash('danger', 'Phone number and password are required.');
    return res.redirect('/login');
  }

  // Check account lockout
  if (isAccountLocked(phoneNo)) {
    req.flash('danger', 'Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.');
    return res.redirect('/login');
  }

  // Admin login — credentials from environment variables
  if (
    process.env.ADMIN_PHONE &&
    process.env.ADMIN_PASSWORD_HASH &&
    phoneNo === process.env.ADMIN_PHONE &&
    bcrypt.compareSync(password, process.env.ADMIN_PASSWORD_HASH)
  ) {
    clearFailedAttempts(phoneNo);
    req.session.regenerate((err) => {
      if (err) {
        req.flash('danger', 'Login error. Please try again.');
        return res.redirect('/login');
      }
      req.session.user_type = 'admin';
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.save(() => res.redirect('/admin'));
    });
    return;
  }

  try {
    // User login
    const user = (await db.query(
      'SELECT uid, name, lastname, ph_no, password FROM users WHERE ph_no = $1',
      [phoneNo]
    )).rows[0];

    if (user && bcrypt.compareSync(password, user.password)) {
      clearFailedAttempts(phoneNo);
      req.session.regenerate((err) => {
        if (err) {
          req.flash('danger', 'Login error. Please try again.');
          return res.redirect('/login');
        }
        req.session.user_type = 'user';
        req.session.user_id = user.uid;
        req.session.user_name = user.name;
        req.session.user_lastname = user.lastname;
        req.session.user_phone = user.ph_no;
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
        req.session.save(() => res.redirect('/success'));
      });
      return;
    }

    // Instructor login
    const instructor = (await db.query(
      'SELECT tid, name, lastname, ph_no, password FROM instructors WHERE ph_no = $1',
      [phoneNo]
    )).rows[0];

    if (instructor && bcrypt.compareSync(password, instructor.password)) {
      clearFailedAttempts(phoneNo);
      req.session.regenerate((err) => {
        if (err) {
          req.flash('danger', 'Login error. Please try again.');
          return res.redirect('/login');
        }
        req.session.user_type = 'instructor';
        req.session.instructor_id = instructor.tid;
        req.session.user_name = instructor.name;
        req.session.user_lastname = instructor.lastname;
        req.session.user_phone = instructor.ph_no;
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
        req.session.save(() => res.redirect('/instructor_dashboard'));
      });
      return;
    }

    recordFailedAttempt(phoneNo);
    req.flash('danger', 'Invalid phone number or password.');
    return res.redirect('/login');
  } catch (err) {
    console.error('Login error:', err);
    req.flash('danger', 'An error occurred. Please try again.');
    return res.redirect('/login');
  }
});

// Apply (Instructor Application)
app.get('/apply', (req, res) => {
  const messages = req.flash();
  res.render('appl', { messages });
});

app.post('/apply', [
  body('fname').trim().isLength({ min: 1, max: 100 }),
  body('lname').trim().isLength({ min: 1, max: 100 }),
  body('phone').matches(/^[+]?[0-9\s\-]{7,20}$/),
  body('password').isLength({ min: 8, max: 100 }),
  body('dob-date').isInt({ min: 1, max: 31 }),
  body('dob-month').isInt({ min: 1, max: 12 }),
  body('dob-year').isInt({ min: 1900, max: new Date().getFullYear() }),
  body('postal').trim().isLength({ min: 1, max: 20 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', 'Invalid input. Please check your details.');
    return res.redirect('/apply');
  }

  const {
    fname, lname,
    'dob-date': dob_day,
    'dob-month': dob_month,
    'dob-year': dob_year,
    address, address2, city, state, postal,
    phone, hear, password
  } = req.body;

  const dob = `${dob_year}-${String(dob_month).padStart(2,'0')}-${String(dob_day).padStart(2,'0')}`;
  const fullAddress = `${address}, ${address2 || ''}, ${city}, ${state}, ${postal}`;

  try {
    const existing = (await db.query('SELECT ph_no FROM instructors WHERE ph_no = $1', [phone])).rows[0];
    if (existing) {
      req.flash('error', 'Phone number already registered. Please use a different number.');
      return res.redirect('/apply');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      'INSERT INTO instructors (name, lastname, ph_no, dob, address, reference, password) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [fname, lname, phone, dob, fullAddress, hear, hashedPassword]
    );

    req.flash('success', 'Application submitted successfully!');
    return res.render('teachercart');
  } catch (err) {
    console.error('Instructor application error:', err);
    req.flash('error', 'Application failed. Please try again.');
    return res.redirect('/apply');
  }
});

// Instructor Dashboard
app.get('/instructor_dashboard', requireInstructor, async (req, res) => {
  try {
    const tid = req.session.instructor_id;

    const { rows: instructor_courses } = await db.query(`
      SELECT i.name, i.lastname, c.course_name
      FROM instructors i
      JOIN instructor_teaching it ON i.tid = it.tid
      JOIN course c ON it.cid = c.cid
      WHERE i.tid = $1
    `, [tid]);

    const instructor_name = instructor_courses.length > 0
      ? `${instructor_courses[0].name} ${instructor_courses[0].lastname}`
      : (req.session.user_name ? `${req.session.user_name} ${req.session.user_lastname || ''}`.trim() : '');

    const { rows: students_data } = await db.query(`
      SELECT u.name, u.lastname, c.course_name
      FROM users u
      JOIN applicants a ON u.uid = a.uid
      JOIN course c ON a.cid = c.cid
      JOIN instructor_teaching it ON c.cid = it.cid
      WHERE it.tid = $1
    `, [tid]);

    const students_by_course = {};
    for (const row of students_data) {
      if (!students_by_course[row.course_name]) {
        students_by_course[row.course_name] = [];
      }
      students_by_course[row.course_name].push(`${row.name} ${row.lastname}`);
    }

    const { rows: learning_rows } = await db.query(
      'SELECT course_name FROM instructor_learning WHERE tid = $1', [tid]
    );
    const learning_courses = learning_rows.map(r => r.course_name);

    return res.render('teach_dashboard', {
      instructor_name,
      students_by_course,
      learning_courses
    });
  } catch (err) {
    console.error('Instructor dashboard error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Success (post-login landing)
app.get('/success', (req, res) => {
  if (!req.session.user_id) {
    req.flash('warning', 'You need to be logged in to access this page.');
    return res.redirect('/login');
  }
  res.render('index', {
    courses: [],
    user_name: req.session.user_name,
    user_lastname: req.session.user_lastname
  });
});

// ─── Admin ───────────────────────────────────────────────────────────────────

app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const total_enrollments = Number((await db.query('SELECT COUNT(DISTINCT uid) AS count FROM applicants')).rows[0].count);
    const total_instructors = Number((await db.query('SELECT COUNT(*) AS count FROM instructors')).rows[0].count);
    const total_courses = Number((await db.query('SELECT COUNT(*) AS count FROM course')).rows[0].count);
    const income_row = (await db.query('SELECT SUM(course.price) AS sum FROM course INNER JOIN applicants ON course.cid = applicants.cid')).rows[0];
    const total_income = income_row.sum || 0;
    const { rows: new_students } = await db.query(`
      SELECT DISTINCT u.name, u.lastname
      FROM applicants a
      JOIN users u ON a.uid = u.uid
      LIMIT 10
    `);

    return res.render('admin', {
      total_enrollments,
      total_instructors,
      total_courses,
      total_income,
      new_students
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/');
  }
});

// ─── Enrollments ─────────────────────────────────────────────────────────────

app.get('/edit_enrollments', requireAdmin, async (req, res) => {
  try {
    const { rows: enrollments } = await db.query(`
      SELECT users.uid, users.name, users.lastname,
             string_agg(course.course_name, ', ') AS course_names,
             SUM(course.price) AS total_fees, MAX(applicants.appid) AS appid
      FROM applicants
      JOIN users ON applicants.uid = users.uid
      JOIN course ON applicants.cid = course.cid
      GROUP BY users.uid, users.name, users.lastname
    `);
    return res.render('enrollments', { enrollments });
  } catch (err) {
    console.error('Edit enrollments error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/admin');
  }
});

app.post('/delete_enrollment/:appid', requireAdmin, async (req, res) => {
  const appid = parseInt(req.params.appid);
  if (!Number.isFinite(appid) || appid <= 0) {
    return res.status(400).send('Invalid ID');
  }
  try {
    const user = (await db.query('SELECT uid FROM applicants WHERE appid = $1', [appid])).rows[0];
    if (user) {
      await db.query('DELETE FROM applicants WHERE appid = $1', [appid]);
      await db.query('DELETE FROM users WHERE uid = $1', [user.uid]);
      req.flash('success', 'Enrollment and user deleted successfully!');
    } else {
      req.flash('error', 'User not found or already deleted.');
    }
    return res.redirect('/edit_enrollments');
  } catch (err) {
    console.error('Delete enrollment error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/edit_enrollments');
  }
});

// ─── Instructors ─────────────────────────────────────────────────────────────

app.get('/edit_instructors', requireAdmin, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT i.tid, i.name, i.lastname, i.ph_no, i.address,
             c.cid, c.course_name, il.course_name AS learning_course
      FROM instructors i
      LEFT JOIN instructor_teaching it ON i.tid = it.tid
      LEFT JOIN course c ON it.cid = c.cid
      LEFT JOIN instructor_learning il ON i.tid = il.tid
    `);

    const instructorsMap = {};
    for (const row of rows) {
      if (!instructorsMap[row.tid]) {
        instructorsMap[row.tid] = {
          tid: row.tid,
          name: row.name,
          lastname: row.lastname,
          phone: row.ph_no,
          address: row.address,
          courses: [],
          learning_courses: []
        };
      }
      if (row.cid) {
        if (!instructorsMap[row.tid].courses.find(c => c.cid === row.cid)) {
          instructorsMap[row.tid].courses.push({ cid: row.cid, name: row.course_name });
        }
      }
      if (row.learning_course && !instructorsMap[row.tid].learning_courses.includes(row.learning_course)) {
        instructorsMap[row.tid].learning_courses.push(row.learning_course);
      }
    }
    const instructors = Object.values(instructorsMap);
    const { rows: all_courses } = await db.query('SELECT cid AS "CID", course_name AS "Course_name" FROM course');

    return res.render('instructors', { instructors, all_courses });
  } catch (err) {
    console.error('Edit instructors error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/admin');
  }
});

app.post('/add_instructor_course/:tid', requireAdmin, async (req, res) => {
  const tid = parseInt(req.params.tid);
  if (!Number.isFinite(tid) || tid <= 0) return res.status(400).send('Invalid ID');
  const course_id = parseInt(req.body.course);
  if (!Number.isFinite(course_id) || course_id <= 0) return res.status(400).send('Invalid course ID');
  try {
    await db.query('INSERT INTO instructor_teaching (tid, cid) VALUES ($1, $2)', [tid, course_id]);
    req.flash('success', 'Course added successfully!');
  } catch (err) {
    console.error('Add instructor course error:', err);
    req.flash('error', 'An error occurred. Please try again.');
  }
  return res.redirect('/edit_instructors');
});

app.post('/remove_instructor_course/:tid/:cid', requireAdmin, async (req, res) => {
  const tid = parseInt(req.params.tid);
  const cid = parseInt(req.params.cid);
  if (!Number.isFinite(tid) || tid <= 0 || !Number.isFinite(cid) || cid <= 0) {
    return res.status(400).send('Invalid ID');
  }
  try {
    await db.query('DELETE FROM instructor_teaching WHERE tid = $1 AND cid = $2', [tid, cid]);
    req.flash('success', 'Course removed successfully!');
  } catch (err) {
    console.error('Remove instructor course error:', err);
    req.flash('error', 'An error occurred. Please try again.');
  }
  return res.redirect('/edit_instructors');
});

app.post('/delete_instructor_enrollment/:tid', requireAdmin, async (req, res) => {
  const tid = parseInt(req.params.tid);
  if (!Number.isFinite(tid) || tid <= 0) return res.status(400).send('Invalid ID');
  try {
    await db.query('DELETE FROM instructors WHERE tid = $1', [tid]);
    req.flash('success', 'Instructor and their data deleted successfully!');
  } catch (err) {
    console.error('Delete instructor error:', err);
    req.flash('error', 'An error occurred. Please try again.');
  }
  return res.redirect('/edit_instructors');
});

// ─── Courses ─────────────────────────────────────────────────────────────────

app.get('/edit_course', requireAdmin, async (req, res) => {
  try {
    const { rows: courses } = await db.query('SELECT cid AS "CID", course_name AS "Course_name", price AS "Price", from_date, to_date FROM course');
    return res.render('course', { courses });
  } catch (err) {
    console.error('Edit course error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/admin');
  }
});

app.post('/edit_course', requireAdmin, [
  body('price').optional().isFloat({ min: 0 }),
  body('course_name').optional().trim().isLength({ min: 1, max: 200 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', 'Invalid input. Please check your details.');
    return res.redirect('/edit_course');
  }
  try {
    if (req.body.course_id) {
      const course_id = parseInt(req.body.course_id);
      if (!Number.isFinite(course_id) || course_id <= 0) return res.status(400).send('Invalid ID');
      const { from_date, to_date } = req.body;
      await db.query('UPDATE course SET from_date = $1, to_date = $2 WHERE cid = $3', [from_date, to_date, course_id]);
      req.flash('success', 'Course dates updated successfully!');
    } else {
      const { course_name, price, from_date, to_date } = req.body;
      await db.query(
        'INSERT INTO course (course_name, price, from_date, to_date) VALUES ($1, $2, $3, $4)',
        [course_name, price, from_date, to_date]
      );
      req.flash('success', 'Course added successfully!');
    }
    return res.redirect('/edit_course');
  } catch (err) {
    console.error('Edit course POST error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/edit_course');
  }
});

app.post('/delete_course/:course_id', requireAdmin, async (req, res) => {
  const course_id = parseInt(req.params.course_id);
  if (!Number.isFinite(course_id) || course_id <= 0) return res.status(400).send('Invalid ID');
  try {
    await db.query('DELETE FROM course WHERE cid = $1', [course_id]);
    req.flash('success', 'Course deleted successfully!');
  } catch (err) {
    console.error('Delete course error:', err);
    req.flash('error', 'An error occurred. Please try again.');
  }
  return res.redirect('/edit_course');
});

// ─── Process Payment ─────────────────────────────────────────────────────────

app.post('/process_payment', requireUser, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.json({ success: false, error: 'Invalid payment data' });
  }

  // Verify the stored order_id matches what was sent (prevent order substitution)
  if (razorpay_order_id !== req.session.order_id) {
    return res.json({ success: false, error: 'Order mismatch' });
  }

  // Verify Razorpay payment signature
  const hmacBody = `${razorpay_order_id}|${razorpay_payment_id}`;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(hmacBody)
    .digest('hex');

  let sigValid = false;
  try {
    sigValid = crypto.timingSafeEqual(
      Buffer.from(expectedSignature, 'hex'),
      Buffer.from(razorpay_signature, 'hex')
    );
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    return res.json({ success: false, error: 'Payment verification failed' });
  }

  // Use session data — never trust the client for user identity or course list
  const user_id = req.session.user_id;
  const courses = req.session.courses || [];

  try {
    for (const course_name of courses) {
      const { rows: [course] } = await db.query('SELECT cid FROM course WHERE course_name = $1', [course_name]);
      if (course) {
        try {
          await db.query('INSERT INTO applicants (uid, cid) VALUES ($1, $2)', [user_id, course.cid]);
        } catch {
          // Ignore duplicate entry errors
        }
      }
    }
    // Clear payment session data after successful enrollment
    delete req.session.order_id;
    delete req.session.courses;
    delete req.session.amount;
    return res.json({ success: true });
  } catch (err) {
    console.error('Process payment error:', err);
    return res.json({ success: false, error: 'An error occurred. Please try again.' });
  }
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong. Please try again later.');
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Indramala Yoga server running at http://localhost:${PORT}`);
  });
}

module.exports = app;
