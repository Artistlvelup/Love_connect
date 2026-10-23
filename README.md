# Love Connect

A separate, worldwide adult dating and connections platform. This repository is not connected to Artist Level Up.

## Features in this initial integrated build
- Account registration and login with password hashing and server sessions
- Profile editing and discovery feed
- Likes and mutual-match creation
- Private text messaging between matched members
- Profile video upload with server-side duration validation (maximum 30 seconds; 10 MB cap for the initial test)
- Report and block endpoints
- Subscription plan display and sponsored-placement UI groundwork

## Run locally
1. Install Node.js 20 or newer and PostgreSQL.
2. Create a PostgreSQL database.
3. Set environment variables:
   - `DATABASE_URL`
   - `SESSION_SECRET` (long random secret)
   - `NODE_ENV=development` (optional)
4. Run `npm install`, then `npm start`.
5. Open `http://localhost:3000`.

The server creates its application tables on startup.

## Important before public launch
- This app is not deployed by committing files to GitHub.
- For the one-time test only, the app stores the test video on the server's local filesystem with a 10 MB upload limit. Do not rely on this for launch: on Render Free, uploaded files disappear on restart, spin-down, or redeploy. Before public launch, configure durable video storage and set usage/spending limits. This does not require Supabase.
- Configure a managed PostgreSQL provider and verify its price/free allowance before creating anything billable. This app does not use Supabase.
- Add email verification, password reset, account deletion/data export, age/consent checks, stronger moderation review, abuse monitoring, and production security testing before accepting the public.
- Payment processing and ad networks require separate approved accounts and server-side integrations. The displayed plans and sponsored placements are not payment/ad integrations yet.
- Never put database passwords, session secrets, payment keys, or storage credentials in frontend code or GitHub.
