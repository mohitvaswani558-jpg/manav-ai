import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import multer from 'multer';
import dotenv from 'dotenv';
import { db } from './server/db.ts';
import {
  hashPassword,
  comparePassword,
  createToken,
  requireAuth,
  requireRole,
  AuthenticatedRequest,
  generatePairingCode,
  generateSecureToken,
} from './server/auth.ts';
import { sendVerificationEmail, sendPasswordResetEmail } from './server/email.ts';
import { getQuestionsForStudent } from './server/questionsBank.ts';
import { generateDevelopmentInsight, generateVivekanandaGrowthReport } from './server/gemini.ts';
import { MainGrowthParameter, User } from './src/types/index.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Multer storage setup for real persistent teacher reward uploads
const uploadDir = path.resolve(process.cwd(), 'data', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadDir);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    const safeBase = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_');
    cb(null, `${Date.now()}-${safeBase}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB max
});

// Helper: Format date string as YYYY-MM-DD
function getTodayDateString(): string {
  const d = new Date();
  return d.toISOString().split('T')[0];
}

// ==========================================
// 0. HEALTH & DATABASE STATUS
// ==========================================
app.get('/api/health', async (_req: Request, res: Response) => {
  try {
    // Quick Firestore probe
    await db.challenges.listActive();
    res.json({
      status: 'healthy',
      database: 'Cloud Firestore',
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    res.status(500).json({
      status: 'degraded',
      error: err?.message || 'Database check failed',
      timestamp: new Date().toISOString(),
    });
  }
});

// ==========================================
// 1. AUTHENTICATION & PORTAL ROUTES
// ==========================================

// Rate Limiter Helper (In-Memory)
const authRateLimits = new Map<string, { count: number; resetAt: number }>();
function checkRateLimit(key: string, maxRequests: number, windowMs: number): boolean {
  const now = Date.now();
  const record = authRateLimits.get(key);
  if (!record || now > record.resetAt) {
    authRateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (record.count >= maxRequests) {
    return false;
  }
  record.count++;
  return true;
}

// Register (Student & Teacher)
app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { role, fullName, email, password, confirmPassword, age } = req.body;

    // Rate Limit: 10 registrations per 15 minutes per IP
    if (!checkRateLimit(`reg_${req.ip}`, 10, 15 * 60 * 1000)) {
      res.status(429).json({ error: 'Too many registration attempts. Please try again in 15 minutes.' });
      return;
    }

    if (!role || !['student', 'teacher'].includes(role)) {
      res.status(400).json({ error: 'Valid role (student or teacher) is required.' });
      return;
    }
    if (!fullName || typeof fullName !== 'string' || fullName.trim().length < 2) {
      res.status(400).json({ error: 'Full name must be at least 2 characters.' });
      return;
    }
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      res.status(400).json({ error: 'A valid email address is required.' });
      return;
    }
    // CRITICAL: Preserve password case-sensitivity strictly! Do NOT modify password string.
    if (!password || typeof password !== 'string' || password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters long.' });
      return;
    }
    if (confirmPassword !== undefined && password !== confirmPassword) {
      res.status(400).json({ error: 'Password and confirm password do not match.' });
      return;
    }
    if (role === 'student' && (!age || isNaN(Number(age)) || Number(age) < 5 || Number(age) > 100)) {
      res.status(400).json({ error: 'A valid student age is required.' });
      return;
    }

    const cleanEmail = email.toLowerCase().trim();
    const existing = await db.users.findByEmail(cleanEmail);
    if (existing) {
      res.status(409).json({ error: 'An account with this email already exists. Please log in or reset your password.' });
      return;
    }

    // Hash exact password (case-sensitive)
    const passwordHash = await hashPassword(password);
    const verificationToken = generateSecureToken();
    const verificationTokenExpiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    const pairingCode = generatePairingCode();

    const newUser: User = {
      id: `usr-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      role,
      fullName: fullName.trim(),
      email: cleanEmail,
      age: role === 'student' ? Number(age) : undefined,
      isVerified: false,
      pairingCode,
      createdAt: new Date().toISOString(),
    };

    await db.users.create({
      ...newUser,
      passwordHash,
      verificationOtp: null,
      verificationToken,
      verificationTokenExpiresAt,
      emailVerified: false,
    });

    // Build verification link using APP_URL or request origin
    const appOrigin = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const verificationLink = `${appOrigin}/verify-email?token=${verificationToken}`;

    // Dispatch email via Brevo API in background (non-blocking) to prevent 502 / timeouts on Render
    sendVerificationEmail({
      toEmail: cleanEmail,
      fullName: fullName.trim(),
      verificationLink,
    }).catch(err => {
      console.error('[BACKGROUND EMAIL ERROR] Failed to send verification email:', err);
    });

    res.status(201).json({
      message: 'Account created. We’ve sent a verification link to your email address. Please verify your email before logging in.',
      email: cleanEmail,
      role,
      verificationLinkPreview: verificationLink, // Always provide verification link backup so users can verify instantly on the UI
    });
  } catch (err: any) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed due to a server error. Please try again.' });
  }
});

// Verify Email Token
app.get('/api/auth/verify-email', async (req: Request, res: Response) => {
  try {
    const token = (req.query.token as string) || (req.body.token as string);
    if (!token) {
      res.status(400).json({ error: 'Verification token is required.' });
      return;
    }

    const user = await db.users.findByVerificationToken(token);
    if (!user) {
      res.status(400).json({ error: 'This verification link is invalid or has expired. Please request a new verification email.' });
      return;
    }

    if (user.verificationTokenExpiresAt && Date.now() > user.verificationTokenExpiresAt) {
      res.status(400).json({ error: 'This verification link is invalid or has expired. Please request a new verification email.' });
      return;
    }

    // Mark verified
    const updated = await db.users.update(user.id, {
      isVerified: true,
      emailVerified: true,
      verificationToken: null,
      verificationTokenExpiresAt: null,
      updatedAt: new Date().toISOString(),
    });

    if (!updated) {
      res.status(500).json({ error: 'Failed to update verification status.' });
      return;
    }

    const sessionToken = createToken(updated);
    const profile = updated.role === 'student' ? await db.profiles.getByUserId(updated.id) : null;

    // Create welcome notification
    await db.notifications.create({
      id: `notif-${Date.now()}`,
      userId: updated.id,
      title: 'Welcome to MANAV',
      message: updated.role === 'student'
        ? 'Your development account is verified. Marks show what you know; MANAV helps you see who you are becoming.'
        : 'Welcome to the Teacher Portal. You are now equipped to observe and encourage human potential.',
      type: 'test_ready',
      read: false,
      createdAt: new Date().toISOString(),
    });

    // Set HttpOnly Cookie
    res.cookie('auth_token', sessionToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      message: 'Email verified successfully. You can now continue to your dashboard.',
      token: sessionToken,
      user: {
        id: updated.id,
        role: updated.role,
        fullName: updated.fullName,
        email: updated.email,
        age: updated.age,
        isVerified: true,
        pairingCode: updated.pairingCode,
      },
      onboardingCompleted: profile ? profile.onboardingCompleted : false,
    });
  } catch (err: any) {
    console.error('Verify Email error:', err);
    res.status(500).json({ error: 'Verification failed. Please try again.' });
  }
});

// POST version of Verify Email for SPA form invocation
app.post('/api/auth/verify-email', async (req: Request, res: Response) => {
  const token = req.body.token;
  if (!token) {
    res.status(400).json({ error: 'Verification token is required.' });
    return;
  }

  // Delegate to GET handler logic
  req.query.token = token;
  const user = await db.users.findByVerificationToken(token);
  if (!user || (user.verificationTokenExpiresAt && Date.now() > user.verificationTokenExpiresAt)) {
    res.status(400).json({ error: 'This verification link is invalid or has expired. Please request a new verification email.' });
    return;
  }

  const updated = await db.users.update(user.id, {
    isVerified: true,
    emailVerified: true,
    verificationToken: null,
    verificationTokenExpiresAt: null,
  });

  if (!updated) {
    res.status(500).json({ error: 'Failed to update verification status.' });
    return;
  }

  const sessionToken = createToken(updated);
  const profile = updated.role === 'student' ? await db.profiles.getByUserId(updated.id) : null;

  res.cookie('auth_token', sessionToken, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json({
    message: 'Email verified successfully. You can now continue to your dashboard.',
    token: sessionToken,
    user: {
      id: updated.id,
      role: updated.role,
      fullName: updated.fullName,
      email: updated.email,
      age: updated.age,
      isVerified: true,
      pairingCode: updated.pairingCode,
    },
    onboardingCompleted: profile ? profile.onboardingCompleted : false,
  });
});

// Resend Verification Email
app.post('/api/auth/resend-verification', async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      res.status(400).json({ error: 'Email address is required.' });
      return;
    }

    const cleanEmail = email.toLowerCase().trim();

    // Rate Limit: 3 resends per 15 minutes per email
    if (!checkRateLimit(`resend_${cleanEmail}`, 3, 15 * 60 * 1000)) {
      res.status(429).json({ error: 'Too many verification email requests. Please wait a few minutes.' });
      return;
    }

    const user = await db.users.findByEmail(cleanEmail);
    if (!user) {
      // Generic success to prevent account enumeration
      res.json({ message: 'If an unverified account exists for this email, a new verification link has been sent.' });
      return;
    }

    if (user.isVerified) {
      res.status(400).json({ error: 'This account is already verified. Please log in.' });
      return;
    }

    const newVerificationToken = generateSecureToken();
    const newExpiresAt = Date.now() + 24 * 60 * 60 * 1000;

    await db.users.update(user.id, {
      verificationToken: newVerificationToken,
      verificationTokenExpiresAt: newExpiresAt,
    });

    const appOrigin = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const verificationLink = `${appOrigin}/verify-email?token=${newVerificationToken}`;

    // Dispatch email via Brevo API in background (non-blocking) to prevent 502 / timeouts on Render
    sendVerificationEmail({
      toEmail: cleanEmail,
      fullName: user.fullName,
      verificationLink,
    }).catch(err => {
      console.error('[BACKGROUND EMAIL ERROR] Failed to resend verification email:', err);
    });

    res.json({
      message: 'A new verification email has been dispatched. Please check your inbox.',
      verificationLinkPreview: verificationLink,
    });
  } catch (err: any) {
    console.error('Resend Verification Error:', err);
    res.status(500).json({ error: 'Failed to resend verification email.' });
  }
});

// Login
app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Rate Limit: 10 login attempts per 15 mins
    if (!checkRateLimit(`login_${req.ip}`, 10, 15 * 60 * 1000)) {
      res.status(429).json({ error: 'Too many failed login attempts. Please try again in 15 minutes.' });
      return;
    }

    if (!email || !password) {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }

    const cleanEmail = email.toLowerCase().trim();
    const user = await db.users.findByEmail(cleanEmail);

    // Generic error for invalid credentials
    if (!user) {
      res.status(401).json({ error: 'Incorrect email or password.' });
      return;
    }

    // CRITICAL: Exact case-sensitive password comparison against bcrypt hash
    const validPassword = await comparePassword(password, user.passwordHash);
    if (!validPassword) {
      res.status(401).json({ error: 'Incorrect email or password.' });
      return;
    }

    // MANDATORY EMAIL VERIFICATION CHECK
    if (!user.isVerified) {
      res.status(403).json({
        error: 'Please verify your email address before logging in. Check your inbox for the verification link.',
        requiresVerification: true,
        email: cleanEmail,
      });
      return;
    }

    const sessionToken = createToken(user);
    const profile = user.role === 'student' ? await db.profiles.getByUserId(user.id) : null;

    // Record last login timestamp
    await db.users.update(user.id, { lastLoginAt: new Date().toISOString() });

    // Set HttpOnly auth cookie
    res.cookie('auth_token', sessionToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      message: 'Sign in successful.',
      token: sessionToken,
      user: {
        id: user.id,
        role: user.role,
        fullName: user.fullName,
        email: user.email,
        age: user.age,
        isVerified: true,
        pairingCode: user.pairingCode,
      },
      onboardingCompleted: profile ? profile.onboardingCompleted : true,
    });
  } catch (err: any) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed due to a server error.' });
  }
});

// Forgot Password
app.post('/api/auth/forgot-password', async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      res.status(400).json({ error: 'Email address is required.' });
      return;
    }

    const cleanEmail = email.toLowerCase().trim();

    if (!checkRateLimit(`forgot_${cleanEmail}`, 3, 15 * 60 * 1000)) {
      res.status(429).json({ error: 'Too many password reset requests. Please wait a few minutes.' });
      return;
    }

    const user = await db.users.findByEmail(cleanEmail);
    if (!user) {
      // Prevent account enumeration
      res.json({ message: 'If an account with this email exists, a password reset link has been sent to your inbox.' });
      return;
    }

    const resetToken = generateSecureToken();
    const resetTokenExpiresAt = Date.now() + 60 * 60 * 1000; // 1 hour

    await db.users.update(user.id, {
      resetToken,
      resetTokenExpiresAt,
    });

    const appOrigin = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const resetLink = `${appOrigin}/reset-password?token=${resetToken}`;

    // Dispatch password reset email in background (non-blocking) to prevent 502 / timeouts on Render
    sendPasswordResetEmail({
      toEmail: cleanEmail,
      fullName: user.fullName,
      resetLink,
    }).catch(err => {
      console.error('[BACKGROUND EMAIL ERROR] Failed to send password reset email:', err);
    });

    res.json({
      message: 'If an account with this email exists, a password reset link has been sent to your inbox.',
      resetLinkPreview: resetLink,
    });
  } catch (err: any) {
    console.error('Forgot Password error:', err);
    res.status(500).json({ error: 'Failed to process password reset request.' });
  }
});

// Reset Password
app.post('/api/auth/reset-password', async (req: Request, res: Response) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;

    if (!token) {
      res.status(400).json({ error: 'Password reset token is required.' });
      return;
    }

    // CRITICAL: Preserve password case-sensitivity strictly!
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
      res.status(400).json({ error: 'New password must be at least 6 characters long.' });
      return;
    }

    if (confirmPassword !== undefined && newPassword !== confirmPassword) {
      res.status(400).json({ error: 'Password and confirm password do not match.' });
      return;
    }

    const user = await db.users.findByResetToken(token);
    if (!user || !user.resetTokenExpiresAt || Date.now() > user.resetTokenExpiresAt) {
      res.status(400).json({ error: 'This password reset link is invalid or has expired. Please request a new link.' });
      return;
    }

    // Hash exact new password (case-sensitive)
    const passwordHash = await hashPassword(newPassword);

    await db.users.update(user.id, {
      passwordHash,
      resetToken: null,
      resetTokenExpiresAt: null,
      updatedAt: new Date().toISOString(),
    });

    res.json({ message: 'Password reset successfully. You can now log in with your new password.' });
  } catch (err: any) {
    console.error('Reset Password error:', err);
    res.status(500).json({ error: 'Failed to reset password.' });
  }
});

// Logout
app.post('/api/auth/logout', (_req: Request, res: Response) => {
  res.clearCookie('auth_token');
  res.json({ success: true, message: 'Logged out successfully.' });
});

// Get Current User (Session Restoration)
app.get('/api/auth/me', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const profile = user.role === 'student' ? await db.profiles.getByUserId(user.id) : null;
  res.json({
    user: {
      id: user.id,
      role: user.role,
      fullName: user.fullName,
      email: user.email,
      age: user.age,
      isVerified: user.isVerified,
      pairingCode: user.pairingCode,
    },
    onboardingCompleted: profile ? profile.onboardingCompleted : true,
  });
});

// ==========================================
// 2. SCENARIO CHALLENGES & REST ENDPOINTS
// ==========================================

// GET all active challenges
app.get('/api/challenges', async (_req: Request, res: Response) => {
  try {
    const challenges = await db.challenges.listActive();
    res.json({ challenges });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch challenges.' });
  }
});

// GET challenge by ID
app.get('/api/challenges/:id', async (req: Request, res: Response) => {
  try {
    const challenge = await db.challenges.getById(req.params.id);
    if (!challenge) {
      res.status(404).json({ error: 'Challenge not found.' });
      return;
    }
    res.json({ challenge });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch challenge.' });
  }
});

// GET all students
app.get('/api/students', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = req.user!;
    if (user.role !== 'teacher') {
      res.status(403).json({ error: 'Teacher access only.' });
      return;
    }
    const students = await db.users.listStudentsForTeacher(user.id);
    res.json({ students });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch students.' });
  }
});

// GET student by ID
app.get('/api/students/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const student = await db.users.findById(req.params.id);
    if (!student || student.role !== 'student') {
      res.status(404).json({ error: 'Student not found.' });
      return;
    }
    const profile = await db.profiles.getByUserId(student.id);
    res.json({ student, profile });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch student.' });
  }
});

// POST Create Attempt
app.post('/api/attempts', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = req.user!;
    const { challengeId, selectedOption, optionalReasoning, hintsUsed, hintIdsUsed } = req.body;
    if (!challengeId) {
      res.status(400).json({ error: 'Challenge ID is required.' });
      return;
    }

    const now = new Date().toISOString();
    const attempt = await db.attempts.create({
      id: `att-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      studentId: user.id,
      challengeId,
      startedAt: now,
      selectedOption: selectedOption || undefined,
      optionalReasoning: optionalReasoning || undefined,
      hintsUsed: Number(hintsUsed) || 0,
      hintIdsUsed: Array.isArray(hintIdsUsed) ? hintIdsUsed : [],
      completed: false,
      status: 'in_progress',
      createdAt: now,
    });

    res.status(201).json({ attempt });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to create attempt.' });
  }
});

// GET Attempt by ID
app.get('/api/attempts/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const attempt = await db.attempts.getById(req.params.id);
    if (!attempt) {
      res.status(404).json({ error: 'Attempt not found.' });
      return;
    }
    res.json({ attempt });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch attempt.' });
  }
});

// PATCH Update Attempt
app.patch('/api/attempts/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const attempt = await db.attempts.getById(req.params.id);
    if (!attempt) {
      res.status(404).json({ error: 'Attempt not found.' });
      return;
    }
    const updated = await db.attempts.update(req.params.id, req.body);
    res.json({ attempt: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to update attempt.' });
  }
});

// POST Submit Attempt
app.post('/api/attempts/:id/submit', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const attempt = await db.attempts.getById(req.params.id);
    if (!attempt) {
      res.status(404).json({ error: 'Attempt not found.' });
      return;
    }
    const now = new Date().toISOString();
    const updated = await db.attempts.update(req.params.id, {
      ...req.body,
      submittedAt: now,
      completed: true,
      status: 'submitted',
    });
    res.json({ attempt: updated });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to submit attempt.' });
  }
});

// POST Reflections
app.post('/api/reflections', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = req.user!;
    const { attemptId, challengeId, difficulty, changedApproach, whatChanged, whatLearned } = req.body;
    if (!attemptId) {
      res.status(400).json({ error: 'Attempt ID is required.' });
      return;
    }

    const now = new Date().toISOString();
    const ref = await db.reflections.create({
      id: `ref-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      userId: user.id,
      testId: attemptId,
      date: getTodayDateString(),
      mainReflection: whatLearned || 'Reflected on scenario decision.',
      whatLearned: whatLearned || '',
      improveTomorrow: whatChanged || '',
      thoughtProvokingAnswer: '',
      relatedDevelopmentAreas: [],
      createdAt: now,
    });

    res.status(201).json({ reflection: ref });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to save reflection.' });
  }
});

// POST Evaluation / Analyze
app.post('/api/evaluations/analyze', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { attemptId, studentId, challengeId, criteriaResults, strengths, growthAreas, feedback } = req.body;
    if (!attemptId || !studentId) {
      res.status(400).json({ error: 'Attempt ID and student ID are required.' });
      return;
    }

    const now = new Date().toISOString();
    const evaluation = await db.evaluations.create({
      id: `eval-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      attemptId,
      studentId,
      challengeId: challengeId || '',
      status: 'completed',
      criteriaResults: Array.isArray(criteriaResults) ? criteriaResults : [],
      strengths: Array.isArray(strengths) ? strengths : [],
      growthAreas: Array.isArray(growthAreas) ? growthAreas : [],
      feedback: feedback || '',
      insufficientEvidence: false,
      createdAt: now,
    });

    // Save individual growth records
    if (Array.isArray(criteriaResults)) {
      for (const resItem of criteriaResults) {
        await db.growthRecords.add({
          id: `gr-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          studentId,
          attemptId,
          challengeId,
          evaluationId: evaluation.id,
          criterionId: resItem.criterionId,
          criterionName: resItem.criterionName,
          level: resItem.level,
          evidence: resItem.evidence,
          createdAt: now,
        });
      }
    }

    res.status(201).json({ evaluation });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to record evaluation.' });
  }
});

// GET Growth Records for Student
app.get('/api/students/:id/growth', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const studentId = req.params.id;
    const growthRecords = await db.growthRecords.listForStudent(studentId);
    const parameters = await db.evidence.calculateParameters(studentId);
    res.json({ growthRecords, parameters });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch student growth records.' });
  }
});

// ==========================================
// 3. STUDENT ONBOARDING & PROFILE
// ==========================================

app.get('/api/student/profile', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'student') {
    res.status(403).json({ error: 'Student access only.' });
    return;
  }
  const profile = await db.profiles.getByUserId(user.id);
  res.json({ profile });
});

app.post('/api/student/profile', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'student') {
    res.status(403).json({ error: 'Student access only.' });
    return;
  }

  const { developmentGoals, struggles } = req.body;
  if (!Array.isArray(developmentGoals) || developmentGoals.length === 0) {
    res.status(400).json({ error: 'Please select at least one quality you want to develop.' });
    return;
  }
  if (!Array.isArray(struggles) || struggles.length === 0) {
    res.status(400).json({ error: 'Please select at least one struggle or area to improve.' });
    return;
  }

  const updatedProfile = await db.profiles.upsert({
    userId: user.id,
    developmentGoals,
    struggles,
    onboardingCompleted: true,
    updatedAt: new Date().toISOString(),
  });

  // Seed initial baseline evidence for chosen goals
  const existingEvidence = await db.evidence.listForUser(user.id);
  if (existingEvidence.length === 0) {
    const params: MainGrowthParameter[] = ['Confidence', 'Consistency', 'Perseverance', 'Willingness', 'Harmony'];
    for (const p of params) {
      await db.evidence.add({
        id: `ev-init-${p}-${Date.now()}-${Math.random().toString(36).substring(2, 5)}`,
        userId: user.id,
        date: getTodayDateString(),
        parameter: p,
        action: `Set personal development targets and initiated development journey`,
        delta: 5,
        source: 'reflection',
        timestamp: new Date().toISOString(),
      });
    }
  }

  res.json({
    message: 'Development profile saved.',
    profile: updatedProfile,
  });
});

// ==========================================
// 4. DAILY DEVELOPMENT TEST (CORE FEATURE)
// ==========================================

app.get('/api/student/daily-test/today', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'student') {
    res.status(403).json({ error: 'Student access only.' });
    return;
  }

  const today = getTodayDateString();
  let test = await db.tests.getByUserAndDate(user.id, today);

  // If no test or if pending test contains outdated questions, refresh with exact 10 scenario questions
  if (!test || (test.status === 'pending' && (!test.questions || test.questions.length !== 10 || !test.questions[0]?.scenario))) {
    const selectedQuestions = getQuestionsForStudent();

    if (test) {
      test = await db.tests.update(test.id, {
        questions: selectedQuestions,
        startedAt: new Date().toISOString(),
      });
    } else {
      test = await db.tests.create({
        id: `test-${user.id}-${today}`,
        userId: user.id,
        date: today,
        questions: selectedQuestions,
        status: 'pending',
        startedAt: new Date().toISOString(),
      });
    }
  }

  const reflection = test ? await db.reflections.getByTestId(test.id) : null;

  res.json({
    test,
    reflectionSubmitted: !!reflection,
  });
});

// Submit Daily Test
app.post('/api/student/daily-test/submit', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'student') {
    res.status(403).json({ error: 'Student access only.' });
    return;
  }

  const { testId, answers } = req.body;
  if (!testId || !Array.isArray(answers)) {
    res.status(400).json({ error: 'Invalid test submission payload.' });
    return;
  }

  const existingTest = await db.tests.getById(testId);
  if (!existingTest || existingTest.userId !== user.id) {
    res.status(404).json({ error: 'Development test not found.' });
    return;
  }

  if (existingTest.status === 'completed') {
    res.status(400).json({ error: 'Today’s development test has already been completed.' });
    return;
  }

  if (answers.length < 10) {
    res.status(400).json({ error: 'All 10 questions must be answered.' });
    return;
  }

  const profile = await db.profiles.getByUserId(user.id);
  const goals = profile?.developmentGoals || [];
  const struggles = profile?.struggles || [];

  let alignmentScore = 0;
  const strongAreasSet = new Set<string>();
  const attentionAreasSet = new Set<string>();
  const parameterDeltas: { [key in MainGrowthParameter]?: number } = {};
  const parametersAffectedSet = new Set<MainGrowthParameter>();

  const detailedEvaluationInputAnswers: Array<{
    scenarioTitle: string;
    scenarioText: string;
    questionText: string;
    selectedOptionText: string;
    isPreferred: boolean;
    explanation?: string;
    writtenReasoning?: string;
    relatedParameters: MainGrowthParameter[];
  }> = [];

  const updatedQuestions = existingTest.questions.map(q => {
    const submission = answers.find((a: any) => a.questionId === q.id);
    const selectedOption = q.options.find(opt => opt.id === submission?.selectedOptionId);

    if (selectedOption) {
      if (selectedOption.isDevelopmentallyPreferred) {
        alignmentScore += 1;
        q.relatedQualities.forEach(qual => strongAreasSet.add(qual));
      } else {
        q.relatedQualities.forEach(qual => attentionAreasSet.add(qual));
      }

      // Record parameter adjustments
      Object.entries(selectedOption.parameters).forEach(([param, delta]) => {
        const p = param as MainGrowthParameter;
        parameterDeltas[p] = (parameterDeltas[p] || 0) + (delta || 0);
        parametersAffectedSet.add(p);
      });

      detailedEvaluationInputAnswers.push({
        scenarioTitle: q.title || 'Scenario Challenge',
        scenarioText: q.scenario || q.questionText,
        questionText: q.questionText,
        selectedOptionText: selectedOption.text,
        isPreferred: selectedOption.isDevelopmentallyPreferred,
        explanation: selectedOption.explanation,
        writtenReasoning: submission?.writtenResponse || undefined,
        relatedParameters: q.relatedParameters,
      });

      return {
        ...q,
        studentSelectedOptionId: selectedOption.id,
        studentWrittenResponse: submission?.writtenResponse || '',
        hintsUsedCount: submission?.hintsUsedCount || 0,
      };
    }
    return q;
  });

  const parametersAffected = Array.from(parametersAffectedSet);

  // Generate Vivekananda Growth Report using Gemini
  const growthReport = await generateVivekanandaGrowthReport({
    studentName: user.fullName,
    answers: detailedEvaluationInputAnswers,
  });

  const developmentInsight = growthReport.synthesis;
  const now = new Date().toISOString();

  // Record growth evidence for all affected Vivekananda keyfields
  for (const p of parametersAffected) {
    const delta = parameterDeltas[p] || 0;
    const matchingEvidence = growthReport.evidenceBreakdown.find(e => e.keyfield === p);
    const evidenceAction = matchingEvidence
      ? matchingEvidence.how
      : `Practiced scenario decision impacting ${p}`;

    await db.evidence.add({
      id: `ev-test-${testId}-${p}-${Date.now()}-${Math.random().toString(36).substring(2, 5)}`,
      userId: user.id,
      date: existingTest.date,
      parameter: p,
      action: evidenceAction,
      delta: Math.max(-5, Math.min(12, delta)),
      source: 'test',
      timestamp: now,
    });
  }

  // Update test record with full Vivekananda Growth Report
  const completedTest = await db.tests.update(testId, {
    questions: updatedQuestions,
    status: 'completed',
    score: alignmentScore,
    alignmentRating: alignmentScore >= 8 ? 'High Alignment' : alignmentScore >= 5 ? 'Balanced Exploration' : 'Active Growth Phase',
    strongAreas: growthReport.highlightedKeyfields,
    areasNeedingAttention: growthReport.areasForImprovement,
    growthParametersAffected: parametersAffected,
    developmentInsight,
    growthReport,
    completionTimeMinutes: Math.max(1, Math.round((Date.now() - new Date(existingTest.startedAt).getTime()) / 60000)),
    completedAt: now,
  });

  // Create in-app student notification without raw score
  await db.notifications.create({
    id: `notif-test-${Date.now()}`,
    userId: user.id,
    title: 'Development Report Generated',
    message: `You completed today’s 10 scenario challenges. Your Vivekananda Human Development Growth Report is ready. Please record your daily reflection.`,
    type: 'test_completed',
    read: false,
    link: '/reflection',
    createdAt: now,
  });

  // Notify teacher if linked
  if (user.teacherId) {
    await db.notifications.create({
      id: `notif-teacher-${Date.now()}`,
      userId: user.teacherId,
      title: `${user.fullName} Completed Today's Scenarios`,
      message: `${user.fullName} completed the daily scenario challenge cycle. Demonstrated qualities: ${growthReport.highlightedKeyfields.slice(0, 3).join(', ')}.`,
      type: 'test_completed',
      read: false,
      link: `/teacher/student/${user.id}`,
      createdAt: now,
    });
  }

  res.json({
    message: 'Daily development test submitted successfully.',
    test: completedTest,
    requiresReflection: true,
  });
});

// ==========================================
// 5. MANDATORY DAILY REFLECTION & JOURNAL
// ==========================================

app.post('/api/student/reflection', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'student') {
    res.status(403).json({ error: 'Student access only.' });
    return;
  }

  const { testId, mainReflection, whatLearned, improveTomorrow, thoughtProvokingAnswer, relatedDevelopmentAreas } = req.body;
  if (!testId || !mainReflection || mainReflection.trim().length < 10) {
    res.status(400).json({ error: 'Please write a thoughtful reflection (at least 10 characters).' });
    return;
  }

  const test = await db.tests.getById(testId);
  if (!test || test.userId !== user.id) {
    res.status(404).json({ error: 'Associated daily test not found.' });
    return;
  }

  const existing = await db.reflections.getByTestId(testId);
  if (existing) {
    res.status(400).json({ error: 'Reflection for this test has already been submitted.' });
    return;
  }

  const now = new Date().toISOString();
  const newReflection = await db.reflections.create({
    id: `ref-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    userId: user.id,
    testId,
    date: test.date,
    mainReflection: mainReflection.trim(),
    whatLearned: (whatLearned || '').trim(),
    improveTomorrow: (improveTomorrow || '').trim(),
    thoughtProvokingAnswer: (thoughtProvokingAnswer || '').trim(),
    relatedDevelopmentAreas: Array.isArray(relatedDevelopmentAreas) ? relatedDevelopmentAreas : ['Self-awareness', 'Consistency'],
    createdAt: now,
  });

  // Record growth evidence for reflection completion
  await db.evidence.add({
    id: `ev-ref-${newReflection.id}-consist`,
    userId: user.id,
    date: test.date,
    parameter: 'Consistency',
    action: 'Completed mandatory daily reflective journal',
    delta: 8,
    source: 'reflection',
    timestamp: now,
  });
  await db.evidence.add({
    id: `ev-ref-${newReflection.id}-will`,
    userId: user.id,
    date: test.date,
    parameter: 'Willingness',
    action: 'Submitted honest inward evaluation of daily choices',
    delta: 6,
    source: 'reflection',
    timestamp: now,
  });

  // Update streak
  const { streak, milestoneReached } = await db.streaks.recordCompletion(user.id, test.date);

  // Handle milestone
  if (milestoneReached) {
    await db.notifications.create({
      id: `notif-streak-${Date.now()}`,
      userId: user.id,
      title: `🔥 ${streak.currentStreak}-Day Growth Milestone!`,
      message: `Outstanding consistency! You have completed ${streak.currentStreak} consecutive days of self-development activities.`,
      type: 'streak_milestone',
      read: false,
      createdAt: now,
    });

    if (user.teacherId) {
      await db.notifications.create({
        id: `notif-teacher-streak-${Date.now()}`,
        userId: user.teacherId,
        title: `🔥 ${user.fullName} Reached a ${streak.currentStreak}-Day Streak!`,
        message: `${user.fullName} has completed ${streak.currentStreak} consecutive development days. Send an encouragement reward!`,
        type: 'streak_milestone',
        read: false,
        link: `/teacher/student/${user.id}`,
        createdAt: now,
      });
    }
  }

  // Notify teacher of reflection submission
  if (user.teacherId) {
    await db.notifications.create({
      id: `notif-teacher-ref-${Date.now()}`,
      userId: user.teacherId,
      title: `${user.fullName} Submitted Today's Reflection`,
      message: `New reflection journal entry recorded for ${test.date}.`,
      type: 'reflection_submitted',
      read: false,
      link: `/teacher/student/${user.id}`,
      createdAt: now,
    });
  }

  res.status(201).json({
    message: 'Reflection recorded successfully. Daily cycle complete.',
    reflection: newReflection,
    streak,
    milestoneReached,
  });
});

app.get('/api/student/reflections', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const reflections = await db.reflections.listForUser(user.id);
  res.json({ reflections });
});

app.get('/api/student/reflections/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const reflection = await db.reflections.getById(req.params.id);
  if (!reflection) {
    res.status(404).json({ error: 'Reflection not found.' });
    return;
  }
  if (user.role === 'student' && reflection.userId !== user.id) {
    res.status(403).json({ error: 'Unauthorized.' });
    return;
  }
  res.json({ reflection });
});

// ==========================================
// 6. FIVE-PARAMETER GROWTH & VISUALIZATION
// ==========================================

app.get('/api/student/growth', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const studentId = (req.query.studentId as string) || user.id;

  if (user.role === 'student' && studentId !== user.id) {
    res.status(403).json({ error: 'Unauthorized.' });
    return;
  }

  const parameters = await db.evidence.calculateParameters(studentId);
  const evidenceHistory = await db.evidence.listForUser(studentId);
  const testHistory = await db.tests.listForUser(studentId);

  res.json({
    parameters,
    evidenceHistory,
    testHistory,
  });
});

// ==========================================
// 7. CONSISTENCY STREAK
// ==========================================

app.get('/api/student/streak', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const streak = await db.streaks.getForUser(user.id);
  res.json({ streak });
});

// ==========================================
// 8. TEACHER REWARDS & STORAGE
// ==========================================

// Send Reward (Supports file upload or text/link)
app.post('/api/teacher/rewards', requireAuth as any, upload.single('rewardFile') as any, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'teacher') {
    res.status(403).json({ error: 'Teacher access only.' });
    return;
  }

  const { studentId, type, title, content } = req.body;
  if (!studentId || !type || !title) {
    res.status(400).json({ error: 'Student ID, reward type, and title are required.' });
    return;
  }

  const student = await db.users.findById(studentId);
  if (!student || student.role !== 'student') {
    res.status(404).json({ error: 'Target student not found.' });
    return;
  }

  let fileUrl: string | undefined;
  let fileType: string | undefined;
  let fileSize: number | undefined;

  if (type === 'file') {
    if (!req.file) {
      res.status(400).json({ error: 'File upload is required for file-type rewards.' });
      return;
    }
    fileUrl = `/api/storage/files/${req.file.filename}`;
    fileType = req.file.mimetype;
    fileSize = req.file.size;
  } else if (type === 'link') {
    if (!content || !content.startsWith('http')) {
      res.status(400).json({ error: 'A valid URL starting with http:// or https:// is required.' });
      return;
    }
  } else if (type === 'text') {
    if (!content || content.trim().length < 5) {
      res.status(400).json({ error: 'Please provide meaningful encouragement text.' });
      return;
    }
  }

  const now = new Date().toISOString();
  const reward = await db.rewards.create({
    id: `rew-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    teacherId: user.id,
    teacherName: user.fullName,
    studentId,
    studentName: student.fullName,
    type,
    title: title.trim(),
    content: (content || req.file?.originalname || '').trim(),
    fileUrl,
    fileType,
    fileSize,
    createdAt: now,
  });

  // Add to student's persistent storage
  await db.storage.create({
    id: `stg-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    userId: studentId,
    name: title.trim(),
    type: type === 'file' ? 'reward_file' : type === 'link' ? 'reward_link' : 'reward_text',
    senderName: user.fullName,
    url: fileUrl || (type === 'link' ? content : undefined),
    content: type === 'text' ? content : undefined,
    fileSize: fileSize ? `${(fileSize / (1024 * 1024)).toFixed(2)} MB` : undefined,
    createdAt: now,
  });

  // Notify student
  await db.notifications.create({
    id: `notif-rew-${Date.now()}`,
    userId: studentId,
    title: '🎁 New Teacher Reward Received',
    message: `${user.fullName} sent you an encouragement reward: "${title.trim()}".`,
    type: 'reward_received',
    read: false,
    link: '/rewards',
    createdAt: now,
  });

  res.status(201).json({
    message: 'Reward sent successfully.',
    reward,
  });
});

// Student: Get Rewards
app.get('/api/rewards/my-rewards', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const rewards = await db.rewards.listForStudent(user.id);
  res.json({ rewards });
});

// Teacher: Get Sent Rewards
app.get('/api/rewards/teacher-history', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'teacher') {
    res.status(403).json({ error: 'Teacher access only.' });
    return;
  }
  const rewards = await db.rewards.listForTeacher(user.id);
  res.json({ rewards });
});

// My Storage Items
app.get('/api/storage/my-storage', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const items = await db.storage.listForUser(user.id);
  res.json({ items });
});

// Teacher & User Upload to Storage Area
app.post('/api/storage/upload', requireAuth as any, upload.single('file') as any, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (!req.file) {
    res.status(400).json({ error: 'Please select a file to upload from your system.' });
    return;
  }

  const file = req.file;
  const title = (req.body.title || file.originalname || 'Educational Resource').trim();
  const description = (req.body.description || '').trim();
  const shareWithCohort = req.body.shareWithCohort === 'true' || req.body.shareWithCohort === true;
  const targetStudentId = req.body.targetStudentId || null;

  const fileUrl = `/api/storage/files/${file.filename}`;
  const fileSizeMb = (file.size / (1024 * 1024)).toFixed(2);
  const now = new Date().toISOString();

  // Create permanent storage item for teacher
  const newItem = await db.storage.create({
    id: `stg-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    userId: user.id,
    name: title,
    type: 'teacher_file',
    senderName: user.fullName,
    url: fileUrl,
    content: description || file.originalname,
    fileSize: `${fileSizeMb} MB`,
    fileType: file.mimetype,
    sharedWithCohort: shareWithCohort,
    targetStudentId: targetStudentId || undefined,
    createdAt: now,
  });

  // If teacher shared with student storage area:
  if (user.role === 'teacher') {
    if (targetStudentId) {
      const student = await db.users.findById(targetStudentId);
      if (student) {
        await db.storage.create({
          id: `stg-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          userId: student.id,
          name: title,
          type: 'teacher_file',
          senderName: user.fullName,
          url: fileUrl,
          content: description || file.originalname,
          fileSize: `${fileSizeMb} MB`,
          fileType: file.mimetype,
          createdAt: now,
        });

        await db.notifications.create({
          id: `notif-stg-${Date.now()}`,
          userId: student.id,
          title: '📁 New Learning Resource Added',
          message: `${user.fullName} uploaded a new resource to your storage: "${title}".`,
          type: 'reward_received',
          read: false,
          link: '/storage',
          createdAt: now,
        });
      }
    } else if (shareWithCohort) {
      const students = await db.users.listStudentsForTeacher(user.id);
      for (const st of students) {
        await db.storage.create({
          id: `stg-${Date.now()}-${Math.random().toString(36).substring(2, 6)}-${st.id}`,
          userId: st.id,
          name: title,
          type: 'teacher_file',
          senderName: user.fullName,
          url: fileUrl,
          content: description || file.originalname,
          fileSize: `${fileSizeMb} MB`,
          fileType: file.mimetype,
          createdAt: now,
        });

        await db.notifications.create({
          id: `notif-stg-${Date.now()}-${st.id}`,
          userId: st.id,
          title: '📁 New Resource Added to Student Storage',
          message: `${user.fullName} uploaded a new resource for your cohort: "${title}".`,
          type: 'reward_received',
          read: false,
          link: '/storage',
          createdAt: now,
        });
      }
    }
  }

  res.status(201).json({
    message: 'File successfully uploaded and permanently saved in storage area.',
    item: newItem,
  });
});

// Delete Storage Item
app.delete('/api/storage/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const id = req.params.id;
  const deleted = await db.storage.delete(id, user.id);
  if (!deleted) {
    res.status(404).json({ error: 'Storage item not found or unauthorized.' });
    return;
  }
  res.json({ message: 'Storage item removed successfully.' });
});

// Download/View static storage file
app.get('/api/storage/files/:filename', (req: Request, res: Response) => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(uploadDir, filename);

  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: 'File not found.' });
    return;
  }

  res.sendFile(filePath);
});

// ==========================================
// 9. 1-ON-1 MESSAGING
// ==========================================

app.get('/api/messages/thread/:partnerId', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const partnerId = req.params.partnerId;
  const messages = await db.messages.getConversation(user.id, partnerId);
  await db.messages.markRead(user.id, partnerId);
  res.json({ messages });
});

app.post('/api/messages/send', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const { receiverId, text } = req.body;

  if (!receiverId || !text || text.trim().length === 0) {
    res.status(400).json({ error: 'Recipient and message text are required.' });
    return;
  }

  const receiver = await db.users.findById(receiverId);
  if (!receiver) {
    res.status(404).json({ error: 'Recipient not found.' });
    return;
  }

  const now = new Date().toISOString();
  const msg = await db.messages.create({
    id: `msg-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    senderId: user.id,
    senderName: user.fullName,
    senderRole: user.role,
    receiverId,
    receiverName: receiver.fullName,
    text: text.trim(),
    read: false,
    createdAt: now,
  });

  // Notify recipient
  await db.notifications.create({
    id: `notif-msg-${Date.now()}`,
    userId: receiverId,
    title: `💬 New Message from ${user.fullName}`,
    message: text.length > 50 ? `${text.substring(0, 47)}...` : text,
    type: 'message_received',
    read: false,
    link: '/messages',
    createdAt: now,
  });

  res.status(201).json({ message: msg });
});

app.post('/api/messages/mark-read', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const { senderId } = req.body;
  if (senderId) {
    await db.messages.markRead(user.id, senderId);
  }
  res.json({ success: true });
});

app.get('/api/messages/unread-count', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const count = await db.messages.getUnreadCount(user.id);
  res.json({ unreadCount: count });
});

// ==========================================
// 10. NOTIFICATIONS CENTER
// ==========================================

app.get('/api/notifications', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const notifications = await db.notifications.listForUser(user.id);
  res.json({ notifications });
});

app.post('/api/notifications/mark-read', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const { id } = req.body;
  await db.notifications.markRead(user.id, id);
  res.json({ success: true });
});

// ==========================================
// 11. TEACHER PORTAL & OBSERVATIONS
// ==========================================

// List teachers (for students to pick or connect)
app.get('/api/teachers', requireAuth, async (_req: Request, res: Response) => {
  try {
    const teachers = await db.users.listTeachers();
    res.json({ teachers });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch teachers.' });
  }
});

// List students for teacher
app.get('/api/teacher/students', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'teacher') {
    res.status(403).json({ error: 'Teacher access only.' });
    return;
  }

  const students = await db.users.listStudentsForTeacher(user.id);
  const today = getTodayDateString();

  const richStudents = [];
  for (const st of students) {
    const profile = await db.profiles.getByUserId(st.id);
    const streak = await db.streaks.getForUser(st.id);
    const todayTest = await db.tests.getByUserAndDate(st.id, today);
    const reflections = await db.reflections.listForUser(st.id);
    const params = await db.evidence.calculateParameters(st.id);

    richStudents.push({
      id: st.id,
      fullName: st.fullName,
      email: st.email,
      age: st.age,
      pairingCode: st.pairingCode,
      developmentGoals: profile?.developmentGoals || [],
      struggles: profile?.struggles || [],
      currentStreak: streak.currentStreak,
      todayTestCompleted: todayTest?.status === 'completed',
      latestReflectionDate: reflections[0]?.date || null,
      parameters: params,
      createdAt: st.createdAt,
    });
  }

  res.json({ students: richStudents });
});

// Pair student via pairing code or email
app.post('/api/teacher/pair-student', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'teacher') {
    res.status(403).json({ error: 'Teacher access only.' });
    return;
  }

  const { studentCodeOrEmail } = req.body;
  if (!studentCodeOrEmail || typeof studentCodeOrEmail !== 'string') {
    res.status(400).json({ error: 'Please enter a student pairing code (e.g. MM-4821) or email.' });
    return;
  }

  const query = studentCodeOrEmail.trim();
  const student = query.startsWith('MM-')
    ? await db.users.findByPairingCode(query)
    : await db.users.findByEmail(query);

  if (!student || student.role !== 'student') {
    res.status(404).json({ error: 'No student found matching that code or email.' });
    return;
  }

  await db.users.assignStudentToTeacher(student.id, user.id);

  // Notify student
  await db.notifications.create({
    id: `notif-pair-${Date.now()}`,
    userId: student.id,
    title: 'Teacher Connected',
    message: `${user.fullName} is now monitoring and supporting your development journey.`,
    type: 'message_received',
    read: false,
    createdAt: new Date().toISOString(),
  });

  res.json({
    message: `Successfully connected with student ${student.fullName}.`,
    student: {
      id: student.id,
      fullName: student.fullName,
      email: student.email,
      pairingCode: student.pairingCode,
    },
  });
});

// Get Student Detail for Teacher
app.get('/api/teacher/student/:studentId', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'teacher') {
    res.status(403).json({ error: 'Teacher access only.' });
    return;
  }

  const student = await db.users.findById(req.params.studentId);
  if (!student || student.role !== 'student') {
    res.status(404).json({ error: 'Student not found.' });
    return;
  }

  const profile = await db.profiles.getByUserId(student.id);
  const streak = await db.streaks.getForUser(student.id);
  const parameters = await db.evidence.calculateParameters(student.id);
  const evidenceHistory = await db.evidence.listForUser(student.id);
  const testHistory = await db.tests.listForUser(student.id);
  const reflections = await db.reflections.listForUser(student.id);
  const rewards = await db.rewards.listForStudent(student.id);
  const observations = await db.observations.listForStudent(student.id);

  res.json({
    student: {
      id: student.id,
      fullName: student.fullName,
      email: student.email,
      age: student.age,
      pairingCode: student.pairingCode,
      createdAt: student.createdAt,
    },
    profile,
    streak,
    parameters,
    evidenceHistory,
    testHistory,
    reflections,
    rewards,
    observations,
  });
});

// Add Teacher Observation
app.post('/api/teacher/observations', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role !== 'teacher') {
    res.status(403).json({ error: 'Teacher access only.' });
    return;
  }

  const { studentId, note } = req.body;
  if (!studentId || !note || note.trim().length < 5) {
    res.status(400).json({ error: 'Please enter a substantive observation note.' });
    return;
  }

  const student = await db.users.findById(studentId);
  if (!student) {
    res.status(404).json({ error: 'Student not found.' });
    return;
  }

  const now = new Date().toISOString();
  const observation = await db.observations.create({
    id: `obs-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    teacherId: user.id,
    teacherName: user.fullName,
    studentId,
    note: note.trim(),
    observedDate: getTodayDateString(),
    createdAt: now,
  });

  // Add growth evidence for positive teacher feedback
  await db.evidence.add({
    id: `ev-obs-${observation.id}`,
    userId: studentId,
    date: getTodayDateString(),
    parameter: 'Perseverance',
    action: `Teacher observation recorded: "${note.length > 40 ? note.substring(0, 37) + '...' : note}"`,
    delta: 5,
    source: 'teacher_observation',
    timestamp: now,
  });

  res.status(201).json({
    message: 'Teacher observation recorded permanently.',
    observation,
  });
});

// ==========================================
// ERROR HANDLING MIDDLEWARE (Multer & General)
// ==========================================
app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      res.status(400).json({
        error: 'File is too large. The maximum supported upload size is 100 MB.',
      });
      return;
    }
    res.status(400).json({
      error: `Upload failed (${err.code}): ${err.message}`,
    });
    return;
  }
  if (err) {
    console.error('Unhandled request error:', err);
    res.status(500).json({
      error: err.message || 'An unexpected server error occurred.',
    });
    return;
  }
  next();
});

// ==========================================
// VITE DEV SERVER / PRODUCTION SERVING
// ==========================================

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MAN-MAKER backend server running on http://0.0.0.0:${PORT} with Cloud Firestore database.`);
  });
}

startServer();
