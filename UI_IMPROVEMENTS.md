# Indramala Yoga Sansthan — UI Improvement Suggestions

## Table of Contents

1. [Global / Cross-Cutting Issues](#1-global--cross-cutting-issues)
2. [Homepage (`index.ejs`)](#2-homepage-indexejs)
3. [Login Page (`login.ejs`)](#3-login-page-loginejs)
4. [Workshop Page (`workshop.ejs`)](#4-workshop-page-workshopejs)
5. [Gallery Page (`gallery.ejs`)](#5-gallery-page-galleryejs)
6. [Information / Yoga Styles (`information.ejs`)](#6-information--yoga-styles-informationejs)
7. [TTC Courses (`knowabtcourses.ejs`)](#7-ttc-courses-knowabtcoursesejs)
8. [RYT Courses (`knowabtcourses_RYT.ejs`)](#8-ryt-courses-knowabtcourses_rytejs)
9. [Vision & Mission (`visionNmission.ejs`)](#9-vision--mission-visionnmissionejs)
10. [Brochure / Certificates / Syllabus Pages](#10-brochure--certificates--syllabus-pages)
11. [Application Form (`appl.ejs`)](#11-application-form-applejs)
12. [Cart Pages (`addtocart.ejs`, `teachercart.ejs`)](#12-cart-pages-addtocartejs-teachercartejs)
13. [Payment / Invoice (`pay.ejs`)](#13-payment--invoice-payejs)
14. [Admin Dashboard (`admin.ejs`)](#14-admin-dashboard-adminejs)
15. [Manage Instructors (`instructors.ejs`)](#15-manage-instructors-instructorsejs)
16. [Manage Courses (`course.ejs`)](#16-manage-courses-courseejs)
17. [Instructor Dashboard (`teach_dashboard.ejs`)](#17-instructor-dashboard-teach_dashboardejs)
18. [Accessibility (A11y)](#18-accessibility-a11y)
19. [Performance](#19-performance)
20. [Security-Related UI Notes](#20-security-related-ui-notes)

---

## 1. Global / Cross-Cutting Issues

### 1.1 No Shared Layout / Partials
Every page duplicates the `<head>`, navbar, footer, and Google Analytics snippet. This leads to inconsistency and makes updates error-prone.

**Suggestion:** Create EJS partials (`partials/head.ejs`, `partials/navbar.ejs`, `partials/footer.ejs`) and include them via `<%- include('partials/head') %>`. This ensures consistent branding, meta tags, and analytics across all pages.

### 1.2 Inconsistent Navigation
- The navbar only exists on `index.ejs`. All other pages either have a standalone "Back to Home" button or a logo-only header.
- Users cannot navigate between Gallery → Information → Courses without going back to the homepage first.

**Suggestion:** Add a consistent navbar (or at minimum a breadcrumb trail) to every public-facing page so users can navigate freely.

### 1.3 Inconsistent "Back to Home" Button
Pages like `workshop.ejs`, `gallery.ejs`, and `visionNmission.ejs` each re-define the `.back-button` style inline. Others have no back navigation at all.

**Suggestion:** Move the back-button style into a shared CSS file and apply it consistently, or better yet, replace it with the shared navbar.

### 1.4 No Consistent Flash Message Component
Flash messages are rendered differently across pages:
- `login.ejs` checks `flash_messages.danger`
- `workshop.ejs` checks `messages.success`
- `appl.ejs` checks `messages.error` and `messages.success`
- `index.ejs` doesn't display flash messages at all (e.g., registration success/failure is invisible)

**Suggestion:** Create a single `partials/flash.ejs` component that handles all flash types (`success`, `error`, `danger`, `warning`) with consistent styling, and include it on every page.

### 1.5 Too Many CSS Files on the Homepage
The homepage loads **7 separate CSS files** plus 2 external CDNs. This creates render-blocking requests.

**Suggestion:** Bundle/minify CSS into fewer files (e.g., one `main.css`). Consider using a build tool or at minimum combining related stylesheets.

### 1.6 Mixed CDN Libraries
The project loads Flickity, Slick Carousel, Bootstrap JS, jQuery Slim, Popper.js, ScrollReveal, Font Awesome (two different CDNs), and Remix Icons. Many of these overlap in functionality.

**Suggestion:** Standardize on one carousel library (e.g., just Slick or just Flickity, not both). Remove Bootstrap JS if not using Bootstrap components. Remove jQuery Slim and use the full jQuery (already loaded for Slick) or migrate to vanilla JS.

### 1.7 No Loading / Skeleton States
Pages that fetch data (admin, instructors, courses) show nothing while loading.

**Suggestion:** Add simple CSS skeleton loaders or a loading spinner so users know the page is working.

### 1.8 No 404 / Error Page
There's no custom error page. Express will show a raw stack trace or default error.

**Suggestion:** Add an `error.ejs` template and a catch-all Express error handler that renders it.

---

## 2. Homepage (`index.ejs`)

### 2.1 Registration Modal UX
- The modal appears abruptly with no transition/animation.
- There's no way to switch between "Register" and "Login" within the modal — the user must click a small text link.
- The gender field uses raw radio buttons with no styling.

**Suggestion:**
- Add a fade/slide-in animation to the modal.
- Add a tabbed interface (Register | Login) within the modal.
- Style the radio buttons as pill/toggle buttons for a cleaner look.

### 2.2 Course Carousel — Radio Button Approach
The custom carousel uses 14+ hidden radio inputs for navigation, which is fragile and doesn't scale.

**Suggestion:** Replace with a proper JS-driven carousel (you already have Flickity loaded) or use CSS scroll-snap for a modern, accessible alternative.

### 2.3 Spelling Errors in Course Cards
- "Competetive Yoga" → **Competitive Yoga**
- "Preganancy Yoga" → **Pregnancy Yoga**

### 2.4 Testimonials — Placeholder Profile Pictures
All three testimonials use the same `placeholderpfp.jpg`.

**Suggestion:** Use real photos (with permission) or unique avatar colors/initials. Identical photos undermine trust.

### 2.5 Hero Section — No Clear CTA Hierarchy
The hero has "Explore Now" linking to `/knowmore`. The trainers section has "Become a Trainer". The courses section has "Know More". These compete for attention.

**Suggestion:** Make the primary CTA visually dominant (larger, higher contrast). Secondary CTAs should be styled as outlined/ghost buttons.

### 2.7 `wowim` and `yogsec` Sections
These sections just show decorative images (`yoyo.png`, `image.png`) with no heading, text, or semantic purpose. They break the content flow.

**Suggestion:** Either give them purpose (e.g., a stats section, a divider with a meaningful quote) or remove them.

### 2.8 Video Container
The embedded YouTube video has a close button but no open button — it's unclear how users trigger it.

**Suggestion:** Add a visible play button/thumbnail that opens the video overlay, or remove the hidden container and embed the video inline.

---

## 3. Login Page (`login.ejs`)

### 3.1 No "Forgot Password" Option
Users who forget their password have no recovery path.

**Suggestion:** Add a "Forgot Password?" link (even if it just directs to WhatsApp support initially).

### 3.2 No Link Back to Homepage
There's no way to go back to the homepage or registration from the login page.

**Suggestion:** Add a "Back to Home" link and a "Don't have an account? Register" link.

### 3.3 Phone Number Input Uses `type="number"`
This causes issues with leading zeros, scroll-wheel accidentally changing the value, and spinner arrows appearing.

**Suggestion:** Use `type="tel"` with a `pattern` attribute instead.

### 3.4 Decorative Side Images May Overflow on Mobile
The side images (`yogapose3.png`, `yogapose4.png`) may not be hidden properly on small screens.

**Suggestion:** Verify responsive behavior and hide side images below a breakpoint.

---

## 4. Workshop Page (`workshop.ejs`)

### 4.1 Placeholder Content
The workshop description is Lorem Ipsum text. The date says "25th November 2024" which is in the past.

**Suggestion:** Replace with real content or make the workshop data dynamic (fetched from the database).

### 4.2 No Phone Number Validation
The phone input uses `type="tel"` but has no `pattern` attribute.

**Suggestion:** Add `pattern="[0-9]{10}"` and a `title` attribute to guide users.

### 4.3 Label `for` Attributes Don't Match
`<label for="name">` doesn't match `<input id="first_name">`, and `<label for="last name">` has a space (invalid) and doesn't match `id="last_name"`.

**Suggestion:** Fix label-input associations: `<label for="first_name">`, `<label for="last_name">`.

---

## 5. Gallery Page (`gallery.ejs`)

### 5.1 No Lightbox
Clicking on an image does nothing. Users can't zoom in to see details.

**Suggestion:** Add a lightweight lightbox (e.g., GLightbox or a simple CSS/JS overlay) so users can view full-size images.

### 5.2 Repetitive Alt Text
Almost every image after the fourth one has the same alt text: "Yoga Event 2".

**Suggestion:** Write unique, descriptive alt text for each image for both accessibility and SEO.

### 5.3 No Lazy Loading
19 full-size PNG images load at once, which is slow on mobile.

**Suggestion:** Add `loading="lazy"` to all `<img>` tags. Consider converting PNGs to WebP.

### 5.4 No Category Filters
All photos are shown in one flat grid.

**Suggestion:** Add filter tabs (e.g., "Classes", "Events", "Instructors", "Poses") to let users browse by interest.

---

## 6. Information / Yoga Styles (`information.ejs`)

### 6.1 Redundant Nested `<div class="logo">`
The logo markup has a `<div class="logo">` nested inside another `<div class="logo">`.

**Suggestion:** Remove the extra wrapper.

### 6.2 No Back Navigation
There's a header with a logo and "INFORMATION" text but no way to go home or to other pages.

**Suggestion:** Make the logo clickable (link to `/`) and add a back button or navbar.

### 6.3 Slider Arrow Confusion
Custom arrow elements (`arrow-left`, `arrow-right`) exist alongside Slick's built-in arrows (set to `false`). This works but is unconventional.

**Suggestion:** Either use Slick's built-in `prevArrow`/`nextArrow` options or keep custom ones — but style them more prominently. They're easy to miss.

### 6.4 "Enroll" Buttons All Link to `/enroll`
Every yoga style has an enroll button, but they all go to the same generic cart page without indicating which course was selected.

**Suggestion:** Pass the course name as a query parameter (e.g., `/enroll?course=hatha-yoga`) and pre-select it on the cart page.

---

## 7. TTC Courses (`knowabtcourses.ejs`)

### 7.1 Duplicate Section Content
The sections for 400-Hour and 800-Hour certifications (the second set) have identical descriptions, eligibility ("Completion of a 800-hour certification"), and images.

**Suggestion:** Create distinct content for each certification level. The duplicate text confuses users.

### 7.2 Duplicate Section ID
`section id="aerial-yoga"` is used for what's actually a "YCB 200-Hour" section (Level 5). IDs should be meaningful and unique.

### 7.3 External Stock Images
Several images are hotlinked from iStockPhoto and Unsplash. These may break or violate terms of service.

**Suggestion:** Download and self-host the images under `/static/assets/`.

---

## 8. RYT Courses (`knowabtcourses_RYT.ejs`)

### 8.1 Same Issues as TTC Page
- No back navigation.
- Nested duplicate `<div class="logo">`.
- External hotlinked images.

### 8.2 No Pricing Information
Neither the TTC nor RYT pages show any pricing, making it hard for users to make enrollment decisions.

**Suggestion:** Add pricing or a "Contact for Pricing" CTA alongside each certification level.

---

## 9. Vision & Mission (`visionNmission.ejs`)

### 9.1 All Styles Are Inline
The entire styling is in a `<style>` block in the `<head>`. This page has no external CSS file.

**Suggestion:** Move styles to a shared or dedicated stylesheet for consistency and cacheability.

### 9.2 Only Two Short Paragraphs
The Vision and Mission sections each contain a single paragraph. This feels sparse.

**Suggestion:** Expand with core values, goals, the founder's philosophy, or key achievements — or condense this into a section on the homepage.

---

## 10. Brochure / Certificates / Syllabus Pages

### 10.1 Bare `<iframe>`-Only Pages
All three pages (`brochure.ejs`, `certificates.ejs`, `Syllabus.ejs`) are just a full-page `<iframe>` embedding a PDF with no header, navbar, or back button.

**Suggestion:**
- Add a header/navbar and back button.
- Add a "Download PDF" button as an alternative (many mobile browsers handle iframe PDFs poorly).
- Show a fallback message for browsers that can't render PDFs.

### 10.2 Fixed `height: 975px`
The iframe height is hardcoded, which won't work well across different screen sizes.

**Suggestion:** Use `height: 100vh` or a responsive approach.

---

## 11. Application Form (`appl.ejs`)

### 11.1 Year Dropdown Hardcoded to 2023 Max
The DOB year dropdown goes up to 2023 only (`for (let y = 1947; y <= 2023; y++)`).

**Suggestion:** Calculate dynamically: `new Date().getFullYear()`.

### 11.2 Misleading Heading
The heading says "Join Our Team" but the subtext says "fill out the form below to buy our courses." These are conflicting messages.

**Suggestion:** Clarify whether this is an instructor application or a course purchase form, and update copy accordingly.

### 11.3 Email Field Collected But Never Used
The form has an email input, but the `/apply` route in `app.js` never reads or stores `req.body.email`.

**Suggestion:** Either store the email in the database or remove the field to avoid confusing users.

### 11.4 No Confirm Password Field
Unlike the registration modal, this form has no password confirmation input.

**Suggestion:** Add a confirm-password field for consistency and safety.

### 11.5 Button Text is "Explore Our Couses"
Spelling error: **Couses → Courses**.

---

## 12. Cart Pages (`addtocart.ejs`, `teachercart.ejs`)

### 12.1 Only Two Products in Student Cart
The student cart (`addtocart.ejs`) only shows "General Yoga" and "Advanced Yoga," regardless of the courses in the database.

**Suggestion:** Dynamically fetch courses from the database and render them, keeping the pricing data flexible.

### 12.2 Payment Manner Silently Resets on Load
`window.onload` sets the dropdowns to "monthly" and "regular," which is fine, but the cart items don't reflect this if the user had a different selection before.

**Suggestion:** Either persist the selection or don't auto-select — let the user choose explicitly.

### 12.3 Cart Sidebar Not Responsive
The sidebar is always visible on desktop, but may overlap or hide on mobile screens.

**Suggestion:** Make the cart sidebar collapsible on mobile (e.g., a slide-out drawer triggered by the cart icon).

### 12.4 Teacher Cart — "Online/Offline" Toggle
The toggle label just says "Offline" with no explanation of what it does.

**Suggestion:** Add a description or tooltip explaining the difference between online and offline modes.

### 12.5 No Empty State Graphics
When the cart is empty, it just says "Your cart is empty" in plain text.

**Suggestion:** Add an illustration or icon (e.g., an empty cart graphic) and a CTA like "Browse Courses."

---

## 13. Payment / Invoice (`pay.ejs`)

### 13.1 Per-Course Price Is Wrong When Multiple Courses Selected
The table shows `amount / 100` for every course row, but `amount` is the **total** — so if 2 courses are purchased, each row shows the full total as the per-item price.

**Suggestion:** Track individual course prices and pass them to the template so each row shows the correct per-item price.

### 13.2 No Print-Friendly Styling
Users may want to print the invoice. The current layout with buttons and no `@media print` rules will look messy.

**Suggestion:** Add `@media print` CSS to hide buttons and optimize the layout for paper.

### 13.3 Address Fields Are Always Empty
`user_address_line_1` and `user_address_line_2` are hardcoded as empty strings in `app.js`.

**Suggestion:** Collect address during registration or at checkout and display it on the invoice.

---

## 14. Admin Dashboard (`admin.ejs`)

### 14.1 "Recent Payments" Table Is Empty
The table exists but has no data. The comment says "Leave table empty for entries."

**Suggestion:** Either populate it with actual payment data from the database or remove the section.

### 14.2 Income Card Links to `income.html`
This links to a static HTML file that likely doesn't exist in the Express app.

**Suggestion:** Create an `/income` route or remove the link.

### 14.3 Placeholder Student Profile Images
All students use `https://via.placeholder.com/50`. This external service may be slow or go offline.

**Suggestion:** Use a local default avatar or CSS initials-based avatars.

### 14.4 No Responsive Design
The admin cards and table layouts are likely not mobile-friendly.

**Suggestion:** Add responsive CSS or use a simple admin CSS framework.

### 14.5 No Back-to-Home Link for Admin
The admin can only sign out; there's no way to go back to the main site.

**Suggestion:** Add a "View Site" link in the header.

---

## 15. Manage Instructors (`instructors.ejs`)

### 15.1 Wide, Unresponsive Table
With 7 columns, the table overflows on smaller screens.

**Suggestion:** Make the table horizontally scrollable (`overflow-x: auto`) or switch to a card layout on mobile.

### 15.2 No Search or Filter
Admins must scroll through all instructors to find one.

**Suggestion:** Add a search bar that filters the table by name or phone number.

### 15.3 Delete Confirmation is JS-Only
The `onsubmit="return confirm(…)"` works, but a styled modal confirmation would be more user-friendly and consistent.

---

## 16. Manage Courses (`course.ejs`)

### 16.1 Date Inputs Not Connected to Form
The "Update Dates" form doesn't include the actual date input values because the date inputs are outside the `<form>` tag.

**Suggestion:** Move the date inputs inside the form, or use JavaScript to copy them into hidden fields before submission.

### 16.2 Price Shows Dollar Sign
Course prices display as `$<%= course.Price %>` but the rest of the site uses Indian Rupees (Rs).

**Suggestion:** Change to `₹` or `Rs` for consistency.

### 16.3 Nested Logo Div (Same as Other Admin Pages)
Redundant `<div class="logo">` wrapping.

---

## 17. Instructor Dashboard (`teach_dashboard.ejs`)

### 17.1 Minimal Design
The dashboard is a single card with bulleted lists. It feels sparse for a dashboard.

**Suggestion:**
- Add summary cards (number of students, upcoming classes).
- Show a schedule or calendar view.
- Add student attendance tracking.

### 17.2 No Feedback if Instructor Has No Courses
If `students_by_course` is empty, the page shows an empty list with no guidance.

**Suggestion:** Show a message like "You haven't been assigned any courses yet. Contact admin."

---

## 18. Accessibility (A11y)

| Issue | Location | Fix |
|-------|----------|-----|
| Missing `alt` text or generic alt | Multiple images across the site | Write descriptive, unique alt text |
| No `aria-label` on icon-only links | Social links, cart icon | Add `aria-label="WhatsApp"`, etc. |
| Color contrast not verified | Green buttons on green-tinted backgrounds | Test with WCAG contrast checker |
| No skip-to-content link | All pages | Add `<a href="#main" class="skip-link">Skip to content</a>` |
| No focus styles visible | Buttons, links | Ensure `:focus-visible` outlines are present |
| Modal not trapping focus | Registration modal on homepage | Trap focus within modal when open |
| Forms missing `<fieldset>` and `<legend>` | Registration, application forms | Group related inputs semantically |
| No `<main>`, `<article>`, `<aside>` landmarks | All pages | Use semantic HTML5 elements |

---

## 19. Performance

| Issue | Impact | Fix |
|-------|--------|-----|
| 7+ CSS files on homepage | Render-blocking | Bundle & minify |
| 19 PNG gallery images loaded eagerly | Slow initial load | `loading="lazy"` + convert to WebP |
| jQuery loaded twice (Slim + Full) | Wasted bandwidth | Load only one |
| ScrollReveal, Flickity, Slick all loaded on homepage | Unused code | Load only what's needed per page |
| External images hotlinked (iStockPhoto, Unsplash) | Unreliable & slow | Self-host |
| No asset cache headers configured | Repeated downloads | Set `Cache-Control` / use fingerprinted filenames |
| Google Analytics loaded on admin pages | Unnecessary | Only include on public-facing pages |

---

## 20. Security-Related UI Notes

> These are UI-visible concerns. Backend security issues exist too but are out of scope for this document.

| Issue | Fix |
|-------|-----|
| Razorpay **test** key visible in HTML source | Use environment variables; never expose secret keys client-side |
| Registration doesn't hash passwords (plaintext in `app.js` `/register`) | Hash with bcrypt before storing |
| Admin credentials hardcoded (`9999999999` / `yogaws`) | Move to env vars or a proper admin user table |
| No CSRF tokens on any form | Add `csurf` or equivalent middleware |
| `confirmpassword` field validated only client-side | Validate password match server-side as well |

---

## Summary of Top 10 Highest-Impact Improvements

| # | Improvement | Effort | Impact |
|---|-------------|--------|--------|
| 1 | **Create shared EJS partials** (head, navbar, footer, flash) | Medium | High — fixes consistency across all pages |
| 2 | **Add consistent navigation** to every page | Medium | High — users can't navigate between pages currently |
| 3 | **Fix flash message rendering** on homepage | Low | High — registration success/failure is invisible |
| 4 | **Add lazy loading + WebP images** | Low | High — massive performance gain on gallery |
| 5 | **Replace placeholder/Lorem Ipsum content** | Low | High — workshop page looks unfinished |
| 6 | **Fix broken form field associations** (labels, date inputs) | Low | Medium — affects usability and accessibility |
| 7 | **Add lightbox to gallery** | Low | Medium — users expect to be able to zoom photos |
| 8 | **Make admin tables responsive** | Medium | Medium — unusable on mobile |
| 9 | **Self-host external images** | Low | Medium — prevents broken images |
| 10 | **Add a 404 error page** | Low | Medium — avoids raw Express errors |
