require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Razorpay = require('razorpay');
const Database = require('better-sqlite3');
const path = require('path');
const flash = require('connect-flash');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

const app = express();

// ─── Security Headers ────────────────────────────────────────────────────────
// contentSecurityPolicy disabled — app uses many inline scripts and external CDNs;
// configure a proper CSP policy before enabling in production.
app.use(helmet({ contentSecurityPolicy: false }));

// ─── View Engine ────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Static Files ────────────────────────────────────────────────────────────
app.use('/static', express.static(path.join(__dirname, 'static')));

// Serve favicon explicitly to satisfy browsers requesting `/favicon.ico`
app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'static', 'assets', 'favicon.ico'));
});

// ─── Body Parsing (with size limits to prevent DoS) ──────────────────────────
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));

// ─── Session ─────────────────────────────────────────────────────────────────
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET not set. Sessions will not survive restart.');
}
app.use(session({
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

// ─── Razorpay Client ─────────────────────────────────────────────────────────
const razorpayClient = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ─── Single DB Connection ─────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'instances', 'YWS.db'));

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
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, please try again later.'
});
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
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
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', 'Invalid input. Please check your details.');
    return res.redirect('/workshop');
  }
  const { first_name, last_name, ph_no, comments = '' } = req.body;
  try {
    db.prepare(`
      INSERT INTO workshop_sign_in (first_name, last_name, Ph_no, Comments)
      VALUES (?, ?, ?, ?)
    `).run(first_name, last_name, ph_no, comments.slice(0, 500));
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
    const order = await razorpayClient.orders.create({
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
    const existing = db.prepare('SELECT Ph_no FROM users WHERE Ph_no = ?').get(phoneNo);
    if (existing) {
      req.flash('error', 'Phone number already registered. Please use a different phone number.');
      return res.redirect('/');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = db.prepare(`
      INSERT INTO users (name, lastname, Ph_no, gender, password)
      VALUES (?, ?, ?, ?, ?)
    `).run(firstName, secondName, phoneNo, Gender, hashedPassword);

    const newUserId = result.lastInsertRowid;
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

app.post('/login', loginLimiter, (req, res) => {
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

  // User login
  const user = db.prepare(
    'SELECT UID, name, lastname, Ph_no, password FROM users WHERE Ph_no = ?'
  ).get(phoneNo);

  if (user && bcrypt.compareSync(password, user.password)) {
    clearFailedAttempts(phoneNo);
    req.session.regenerate((err) => {
      if (err) {
        req.flash('danger', 'Login error. Please try again.');
        return res.redirect('/login');
      }
      req.session.user_type = 'user';
      req.session.user_id = user.UID;
      req.session.user_name = user.name;
      req.session.user_lastname = user.lastname;
      req.session.user_phone = user.Ph_no;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.save(() => res.redirect('/success'));
    });
    return;
  }

  // Instructor login
  const instructor = db.prepare(
    'SELECT TID, name, lastname, Ph_no, password FROM instructors WHERE Ph_no = ?'
  ).get(phoneNo);

  if (instructor && bcrypt.compareSync(password, instructor.password)) {
    clearFailedAttempts(phoneNo);
    req.session.regenerate((err) => {
      if (err) {
        req.flash('danger', 'Login error. Please try again.');
        return res.redirect('/login');
      }
      req.session.user_type = 'instructor';
      req.session.instructor_id = instructor.TID;
      req.session.user_name = instructor.name;
      req.session.user_lastname = instructor.lastname;
      req.session.user_phone = instructor.Ph_no;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.save(() => res.redirect('/instructor_dashboard'));
    });
    return;
  }

  recordFailedAttempt(phoneNo);
  req.flash('danger', 'Invalid phone number or password.');
  return res.redirect('/login');
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
    const existing = db.prepare('SELECT Ph_no FROM instructors WHERE Ph_no = ?').get(phone);
    if (existing) {
      req.flash('error', 'Phone number already registered. Please use a different number.');
      return res.redirect('/apply');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    db.prepare(`
      INSERT INTO instructors (name, lastname, Ph_no, DOB, Address, reference, password)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(fname, lname, phone, dob, fullAddress, hear, hashedPassword);

    req.flash('success', 'Application submitted successfully!');
    return res.render('teachercart');
  } catch (err) {
    console.error('Instructor application error:', err);
    req.flash('error', 'Application failed. Please try again.');
    return res.redirect('/apply');
  }
});

// Instructor Dashboard
app.get('/instructor_dashboard', requireInstructor, (req, res) => {
  try {
    const tid = req.session.instructor_id;

    const instructor_courses = db.prepare(`
      SELECT i.name, i.lastname, c.Course_name
      FROM instructors i
      JOIN instructor_teaching it ON i.TID = it.TID
      JOIN course c ON it.CID = c.CID
      WHERE i.TID = ?
    `).all(tid);

    const instructor_name = instructor_courses.length > 0
      ? `${instructor_courses[0].name} ${instructor_courses[0].lastname}`
      : (req.session.user_name ? `${req.session.user_name} ${req.session.user_lastname || ''}`.trim() : '');

    const students_data = db.prepare(`
      SELECT u.name, u.lastname, c.Course_name
      FROM users u
      JOIN applicants a ON u.UID = a.UID
      JOIN course c ON a.CID = c.CID
      JOIN instructor_teaching it ON c.CID = it.CID
      WHERE it.TID = ?
    `).all(tid);

    const students_by_course = {};
    for (const row of students_data) {
      if (!students_by_course[row.Course_name]) {
        students_by_course[row.Course_name] = [];
      }
      students_by_course[row.Course_name].push(`${row.name} ${row.lastname}`);
    }

    const learning_rows = db.prepare(
      'SELECT Course_name FROM instructor_learning WHERE TID = ?'
    ).all(tid);
    const learning_courses = learning_rows.map(r => r.Course_name);

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

app.get('/admin', requireAdmin, (req, res) => {
  try {
    const total_enrollments = db.prepare('SELECT COUNT(DISTINCT UID) FROM applicants').get()['COUNT(DISTINCT UID)'];
    const total_instructors = db.prepare('SELECT COUNT(*) FROM instructors').get()['COUNT(*)'];
    const total_courses = db.prepare('SELECT COUNT(*) FROM course').get()['COUNT(*)'];
    const income_row = db.prepare('SELECT SUM(course.Price) FROM course INNER JOIN applicants ON course.CID = applicants.CID').get();
    const total_income = income_row['SUM(course.Price)'] || 0;
    const new_students = db.prepare(`
      SELECT DISTINCT u.name, u.lastname
      FROM applicants a
      JOIN users u ON a.UID = u.UID
      LIMIT 10
    `).all();

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

app.get('/edit_enrollments', requireAdmin, (req, res) => {
  try {
    const enrollments = db.prepare(`
      SELECT users.UID, users.name, users.lastname,
             GROUP_CONCAT(course.Course_name, ', ') AS Course_names,
             SUM(course.Price) AS Total_Fees, applicants.APPID
      FROM applicants
      JOIN users ON applicants.UID = users.UID
      JOIN course ON applicants.CID = course.CID
      GROUP BY users.UID
    `).all();
    return res.render('enrollments', { enrollments });
  } catch (err) {
    console.error('Edit enrollments error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/admin');
  }
});

app.post('/delete_enrollment/:appid', requireAdmin, (req, res) => {
  const appid = parseInt(req.params.appid);
  if (!Number.isFinite(appid) || appid <= 0) {
    return res.status(400).send('Invalid ID');
  }
  try {
    const user = db.prepare('SELECT UID FROM applicants WHERE APPID = ?').get(appid);
    if (user) {
      db.prepare('DELETE FROM applicants WHERE APPID = ?').run(appid);
      db.prepare('DELETE FROM users WHERE UID = ?').run(user.UID);
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

app.get('/edit_instructors', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT i.TID, i.name, i.lastname, i.Ph_no, i.Address,
             c.CID, c.Course_name, il.Course_name AS learning_course
      FROM instructors i
      LEFT JOIN instructor_teaching it ON i.TID = it.TID
      LEFT JOIN course c ON it.CID = c.CID
      LEFT JOIN instructor_learning il ON i.TID = il.TID
    `).all();

    const instructorsMap = {};
    for (const row of rows) {
      if (!instructorsMap[row.TID]) {
        instructorsMap[row.TID] = {
          tid: row.TID,
          name: row.name,
          lastname: row.lastname,
          phone: row.Ph_no,
          address: row.Address,
          courses: [],
          learning_courses: []
        };
      }
      if (row.CID) {
        if (!instructorsMap[row.TID].courses.find(c => c.cid === row.CID)) {
          instructorsMap[row.TID].courses.push({ cid: row.CID, name: row.Course_name });
        }
      }
      if (row.learning_course && !instructorsMap[row.TID].learning_courses.includes(row.learning_course)) {
        instructorsMap[row.TID].learning_courses.push(row.learning_course);
      }
    }
    const instructors = Object.values(instructorsMap);
    const all_courses = db.prepare('SELECT CID, Course_name FROM course').all();

    return res.render('instructors', { instructors, all_courses });
  } catch (err) {
    console.error('Edit instructors error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/admin');
  }
});

app.post('/add_instructor_course/:tid', requireAdmin, (req, res) => {
  const tid = parseInt(req.params.tid);
  if (!Number.isFinite(tid) || tid <= 0) return res.status(400).send('Invalid ID');
  const course_id = parseInt(req.body.course);
  if (!Number.isFinite(course_id) || course_id <= 0) return res.status(400).send('Invalid course ID');
  try {
    db.prepare('INSERT INTO instructor_teaching (TID, CID) VALUES (?, ?)').run(tid, course_id);
    req.flash('success', 'Course added successfully!');
  } catch (err) {
    console.error('Add instructor course error:', err);
    req.flash('error', 'An error occurred. Please try again.');
  }
  return res.redirect('/edit_instructors');
});

app.post('/remove_instructor_course/:tid/:cid', requireAdmin, (req, res) => {
  const tid = parseInt(req.params.tid);
  const cid = parseInt(req.params.cid);
  if (!Number.isFinite(tid) || tid <= 0 || !Number.isFinite(cid) || cid <= 0) {
    return res.status(400).send('Invalid ID');
  }
  try {
    db.prepare('DELETE FROM instructor_teaching WHERE TID = ? AND CID = ?').run(tid, cid);
    req.flash('success', 'Course removed successfully!');
  } catch (err) {
    console.error('Remove instructor course error:', err);
    req.flash('error', 'An error occurred. Please try again.');
  }
  return res.redirect('/edit_instructors');
});

app.post('/delete_instructor_enrollment/:tid', requireAdmin, (req, res) => {
  const tid = parseInt(req.params.tid);
  if (!Number.isFinite(tid) || tid <= 0) return res.status(400).send('Invalid ID');
  try {
    db.prepare('DELETE FROM instructors WHERE TID = ?').run(tid);
    req.flash('success', 'Instructor and their data deleted successfully!');
  } catch (err) {
    console.error('Delete instructor error:', err);
    req.flash('error', 'An error occurred. Please try again.');
  }
  return res.redirect('/edit_instructors');
});

// ─── Courses ─────────────────────────────────────────────────────────────────

app.get('/edit_course', requireAdmin, (req, res) => {
  try {
    const courses = db.prepare('SELECT CID, Course_name, Price, from_date, to_date FROM course').all();
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
], (req, res) => {
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
      db.prepare('UPDATE course SET from_date = ?, to_date = ? WHERE CID = ?')
        .run(from_date, to_date, course_id);
      req.flash('success', 'Course dates updated successfully!');
    } else {
      const { course_name, price, from_date, to_date } = req.body;
      db.prepare('INSERT INTO course (Course_name, Price, from_date, to_date) VALUES (?, ?, ?, ?)')
        .run(course_name, price, from_date, to_date);
      req.flash('success', 'Course added successfully!');
    }
    return res.redirect('/edit_course');
  } catch (err) {
    console.error('Edit course POST error:', err);
    req.flash('error', 'An error occurred. Please try again.');
    return res.redirect('/edit_course');
  }
});

app.post('/delete_course/:course_id', requireAdmin, (req, res) => {
  const course_id = parseInt(req.params.course_id);
  if (!Number.isFinite(course_id) || course_id <= 0) return res.status(400).send('Invalid ID');
  try {
    db.prepare('DELETE FROM course WHERE CID = ?').run(course_id);
    req.flash('success', 'Course deleted successfully!');
  } catch (err) {
    console.error('Delete course error:', err);
    req.flash('error', 'An error occurred. Please try again.');
  }
  return res.redirect('/edit_course');
});

// ─── Process Payment ─────────────────────────────────────────────────────────

app.post('/process_payment', requireUser, (req, res) => {
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
      const course = db.prepare('SELECT CID FROM course WHERE Course_name = ?').get(course_name);
      if (course) {
        try {
          db.prepare('INSERT INTO applicants (UID, CID) VALUES (?, ?)').run(user_id, course.CID);
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
