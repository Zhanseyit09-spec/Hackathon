require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const TelegramBot = require('node-telegram-bot-api');
const { OpenAI } = require('openai');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database(process.env.DATABASE_PATH || path.join(__dirname, 'jobs.db'));
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

db.exec(`
  CREATE TABLE IF NOT EXISTS vacancies (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    title            TEXT,
    company          TEXT,
    skills           TEXT,
    city             TEXT,
    district         TEXT,
    type             TEXT,
    experience       TEXT,
    employer_chat_id TEXT,
    salary           TEXT,
    phone            TEXT,
    requirements     TEXT
  );
  CREATE TABLE IF NOT EXISTS applications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vacancy_id  INTEGER,
    name        TEXT,
    skills      TEXT,
    phone       TEXT,
    chat_id     TEXT,
    city        TEXT,
    district    TEXT,
    experience  TEXT,
    jobtype     TEXT
  );
  CREATE TABLE IF NOT EXISTS web_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT CHECK (role IS NULL OR role IN ('employer', 'seeker')),
    created_at    INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS web_sessions_expiry ON web_sessions(expires_at);
`);

const SESSION_COOKIE = 'job_session';
const SESSION_LIFETIME = 7 * 24 * 60 * 60 * 1000;
const authAttempts = new Map();

function getRequestSessionToken(req) {
  const cookies = (req.headers.cookie || '').split(';');
  for (const cookie of cookies) {
    const separator = cookie.indexOf('=');
    if (separator < 0 || cookie.slice(0, separator).trim() !== SESSION_COOKIE) continue;
    const value = cookie.slice(separator + 1).trim();
    return /^[A-Za-z0-9_-]{40,50}$/.test(value) ? value : null;
  }
  return null;
}

function getRequestUser(req) {
  const token = getRequestSessionToken(req);
  if (!token) return null;
  return db.prepare(
    'SELECT u.id, u.username, u.role FROM web_sessions s ' +
    'JOIN web_users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?'
  ).get(crypto.createHash('sha256').update(token).digest('hex'), Date.now()) || null;
}

function requireRole(req, res, role) {
  const user = getRequestUser(req);
  if (!user) {
    res.status(401).json({ error: 'Жалғастыру үшін алдымен жүйеге кіріңіз.' });
    return null;
  }
  if (!user.role) {
    res.status(403).json({ error: 'Жалғастыру үшін жұмыс беруші немесе жұмыс іздеуші рөлін таңдаңыз.' });
    return null;
  }
  if (role && user.role !== role) {
    res.status(403).json({ error: 'Бұл әрекет сіздің тіркелгі рөліңізге қолжетімсіз.' });
    return null;
  }
  return user;
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    SESSION_COOKIE + '=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800' + secure
  );
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    SESSION_COOKIE + '=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' + secure
  );
}

function isAuthRateLimited(key, limit, windowMs) {
  const now = Date.now();
  const recent = (authAttempts.get(key) || []).filter(function(timestamp) {
    return now - timestamp < windowMs;
  });
  if (recent.length >= limit) {
    authAttempts.set(key, recent);
    return true;
  }
  recent.push(now);
  authAttempts.set(key, recent);
  return false;
}

async function hashPassword(password, salt) {
  return new Promise(function(resolve, reject) {
    crypto.scrypt(password, salt, 64, function(error, derivedKey) {
      if (error) return reject(error);
      return resolve(derivedKey);
    });
  });
}

async function createWebSession(userId, res) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = Date.now() + SESSION_LIFETIME;
  db.prepare('DELETE FROM web_sessions WHERE expires_at <= ?').run(Date.now());
  db.prepare('INSERT INTO web_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(tokenHash, userId, expiresAt);
  setSessionCookie(res, token);
}

const userState = {};

const CITIES = {
  kz: { '1': 'Aktau_kz', '2': 'Zhanaozen_kz', '3': 'Any_kz' },
  ru: { '1': 'Aktau_ru', '2': 'Zhanaozen_ru', '3': 'Any_ru' },
  en: { '1': 'Aktau',    '2': 'Zhanaozen',    '3': 'Anywhere' },
};

const EXPERIENCE = {
  kz: { '1': 'Junior', '2': 'Middle', '3': 'Senior', '4': 'Any_kz' },
  ru: { '1': 'Junior', '2': 'Middle', '3': 'Senior', '4': 'Any_ru' },
  en: { '1': 'Junior', '2': 'Middle', '3': 'Senior', '4': 'Any'    },
};

const SCHEDULE = {
  kz: { '1': 'Tolyk_kun', '2': 'Zhartylai' },
  ru: { '1': 'Polnyi_den', '2': 'Chastichnaya' },
  en: { '1': 'Full time', '2': 'Part time' },
};

const ANY_EXP  = new Set(['Any_kz','Any_ru','Any']);
const ANY_CITY = new Set(['Any_kz','Any_ru','Anywhere']);

const CITY_LABEL = {
  kz: { '1': '\u0410\u049b\u0442\u0430\u0443',   '2': '\u0416\u0430\u04a3\u0430\u04e9\u0437\u0435\u043d' },
  ru: { '1': '\u0410\u043a\u0442\u0430\u0443',   '2': '\u0416\u0430\u043d\u0430\u043e\u0437\u0435\u043d' },
  en: { '1': 'Aktau', '2': 'Zhanaozen' },
};

const SCHEDULE_LABEL = {
  kz: { '1': '\u0422\u043e\u043b\u044b\u049b \u043a\u04af\u043d', '2': '\u0416\u0430\u0440\u0442\u044b\u043b\u0430\u0439' },
  ru: { '1': '\u041f\u043e\u043b\u043d\u044b\u0439 \u0434\u0435\u043d\u044c', '2': '\u0427\u0430\u0441\u0442\u0438\u0447\u043d\u0430\u044f \u0437\u0430\u043d\u044f\u0442\u043e\u0441\u0442\u044c' },
  en: { '1': 'Full time', '2': 'Part time' },
};

const M = {
  kz: {
    welcome:         '\u{1F44B} \u0421\u04d9\u043b\u0435\u043c! \u041c\u0430\u04a3\u0493\u044b\u0441\u0442\u0430\u0443 \u0416\u04b1\u043c\u044b\u0441 \u041f\u043b\u0430\u0442\u0444\u043e\u0440\u043c\u0430\u0441\u044b\u043d\u0430 \u049b\u043e\u0448 \u043a\u0435\u043b\u0434\u0456\u04a3\u0456\u0437!',
    who:             '\u0421\u0456\u0437 \u043a\u0456\u043c\u0441\u0456\u0437?',
    seeker:          '\u{1F50D} \u0416\u04b1\u043c\u044b\u0441 \u0456\u0437\u0434\u0435\u0439\u043c\u0456\u043d',
    employer:        '\u{1F4BC} \u0416\u04b1\u043c\u044b\u0441\u0448\u044b \u0456\u0437\u0434\u0435\u0439\u043c\u0456\u043d',
    browse:          '\u{1F4CB} \u0411\u0430\u0440\u043b\u044b\u049b \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u044f\u043b\u0430\u0440\u0434\u044b \u043a\u04e9\u0440\u0443',
    cancel:          '\u274C \u0411\u043e\u043b\u0434\u044b\u0440\u043c\u0430\u0443',
    cancelled:       '\u274C \u0411\u043e\u043b\u0434\u044b\u0440\u044b\u043b\u043c\u0430\u0434\u044b. /start \u0431\u0430\u0441\u044b\u04a3\u044b\u0437.',
    name:            '\u{1F4DD} \u0410\u0442\u044b\u04a3\u044b\u0437\u0434\u044b \u0436\u0430\u0437\u044b\u04a3\u044b\u0437:',
    skills:          '\u{1F6E0} \u0414\u0430\u0493\u0434\u044b\u043b\u0430\u0440\u044b\u04a3\u044b\u0437\u0434\u044b \u04af\u0442\u0456\u0440 \u0430\u0440\u049b\u044b\u043b\u044b \u0436\u0430\u0437\u044b\u04a3\u044b\u0437:',
    phone:           '\u{1F4DE} \u0422\u0435\u043b\u0435\u0444\u043e\u043d \u043d\u04e9\u043c\u0456\u0440\u0456\u04a3\u0456\u0437\u0434\u0456 \u0436\u0430\u0437\u044b\u04a3\u044b\u0437 (+77001234567):',
    invalidPhone:    '\u26A0\uFE0F \u0422\u0435\u043b\u0435\u0444\u043e\u043d \u0434\u04b1\u0440\u044b\u0441 \u0435\u043c\u0435\u0441. \u049a\u0430\u0439\u0442\u0430 \u0436\u0430\u0437\u044b\u04a3\u044b\u0437:',
    cityFilter:      '\u{1F4CD} \u049a\u0430\u0439 \u049b\u0430\u043b\u0430\u0434\u0430 \u0436\u04b1\u043c\u044b\u0441 \u0456\u0437\u0434\u0435\u0439\u0441\u0456\u0437?\n1. \u0410\u049b\u0442\u0430\u0443\n2. \u0416\u0430\u04a3\u0430\u04e9\u0437\u0435\u043d\n3. \u0411\u0430\u0440\u043b\u044b\u0493\u044b',
    districtFilter:  '\u{1F3D8} \u0428\u0430\u0493\u044b\u043d \u0430\u0443\u0434\u0430\u043d (0 \u0436\u0430\u0437\u0441\u0430\u04a3\u044b\u0437 \u043c\u0430\u04a3\u044b\u0437\u0434\u044b \u0435\u043c\u0435\u0441 \u0431\u043e\u043b\u0441\u0430):',
    scheduleFilter:  '\u{1F554} \u0416\u04b1\u043c\u044b\u0441 \u0442\u04af\u0440\u0456:\n1. \u0422\u043e\u043b\u044b\u049b \u043a\u04af\u043d\n2. \u0416\u0430\u0440\u0442\u044b\u043b\u0430\u0439\n3. \u04e8\u0437\u0433\u0435\n\n0 - \u043c\u0430\u04a3\u044b\u0437\u0434\u044b \u0435\u043c\u0435\u0441',
    scheduleCustom:  '\u270F\uFE0F \u0416\u04b1\u043c\u044b\u0441 \u043a\u0435\u0441\u0442\u0435\u0441\u0456\u043d \u0436\u0430\u0437\u044b\u04a3\u044b\u0437:',
    expFilter:       '\u2B50 \u0422\u04d9\u0436\u0456\u0440\u0438\u0431\u0435 \u0434\u0435\u04a3\u0433\u0435\u0439\u0456:\n1. Junior\n2. Middle\n3. Senior\n4. \u0411\u0430\u0440\u043b\u044b\u0493\u044b',
    saved:           '\u2705 \u04e8\u0442\u0456\u043d\u0456\u0448\u0456\u04a3\u0456\u0437 \u0441\u0430\u049b\u0442\u0430\u043b\u0434\u044b!',
    matched:         '\u2705 \u041c\u04af\u043c\u043a\u0456\u043d \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u044f\u043b\u0430\u0440:\n\n',
    noMatch:         '\u{1F614} \u0412\u0430\u043a\u0430\u043d\u0441\u0438\u044f \u0442\u0430\u0431\u044b\u043b\u043c\u0430\u0434\u044b. \u04e8\u0442\u0456\u043d\u0456\u0448 \u0441\u0430\u049b\u0442\u0430\u043b\u0434\u044b!',
    thinking:        '\u{1F916} AI \u0456\u0437\u0434\u0435\u043f \u0436\u0430\u0442\u044b\u0440...',
    vtitle:          '\u{1F4DD} \u0412\u0430\u043a\u0430\u043d\u0441\u0438\u044f \u0430\u0442\u0430\u0443\u044b\u043d \u0436\u0430\u0437\u044b\u04a3\u044b\u0437:',
    vcompany:        '\u{1F3E2} \u041a\u043e\u043c\u043f\u0430\u043d\u0438\u044f \u0430\u0442\u0430\u0443\u044b\u043d \u0436\u0430\u0437\u044b\u04a3\u044b\u0437:',
    vskills:         '\u{1F6E0} \u049a\u0430\u043d\u0434\u0430\u0439 \u0434\u0430\u0493\u0434\u044b\u043b\u0430\u0440 \u043a\u0435\u0440\u0435\u043a? (\u04af\u0442\u0456\u0440 \u0430\u0440\u049b\u044b\u043b\u044b)',
    vcity:           '\u{1F4CD} \u049a\u0430\u043b\u0430:\n1. \u0410\u049b\u0442\u0430\u0443\n2. \u0416\u0430\u04a3\u0430\u04e9\u0437\u0435\u043d\n3. \u0411\u0430\u0440\u043b\u044b\u0493\u044b',
    vdistrict:       '\u{1F3D8} \u0428\u0430\u0493\u044b\u043d \u0430\u0443\u0434\u0430\u043d (0 \u0436\u043e\u049b \u0431\u043e\u043b\u0441\u0430):',
    vsalary:         '\u{1F4B0} \u0416\u0430\u043b\u0430\u049b\u044b:',
    vschedule:       '\u{1F554} \u0416\u04b1\u043c\u044b\u0441 \u0442\u04af\u0440\u0456:\n1. \u0422\u043e\u043b\u044b\u049b \u043a\u04af\u043d\n2. \u0416\u0430\u0440\u0442\u044b\u043b\u0430\u0439\n3. \u04e8\u0437\u0433\u0435',
    vscheduleCustom: '\u270F\uFE0F \u0416\u04b1\u043c\u044b\u0441 \u043a\u0435\u0441\u0442\u0435\u0441\u0456\u043d \u0436\u0430\u0437\u044b\u04a3\u044b\u0437:',
    vexperience:     '\u2B50 \u049a\u0430\u043d\u0434\u0430\u0439 \u0442\u04d9\u0436\u0456\u0440\u0438\u0431\u0435 \u043a\u0435\u0440\u0435\u043a?\n1. Junior\n2. Middle\n3. Senior\n4. \u0411\u0430\u0440\u043b\u044b\u0493\u044b',
    vrequirements:   '\u{1F4CB} \u0422\u0430\u043b\u0430\u043f\u0442\u0430\u0440 (0 \u0436\u043e\u049b \u0431\u043e\u043b\u0441\u0430):',
    vposted:         '\u2705 \u0412\u0430\u043a\u0430\u043d\u0441\u0438\u044f \u0436\u0430\u0440\u0438\u044f\u043b\u0430\u043d\u0434\u044b!\n\n',
    allVacancies:    '\u{1F4CB} \u0411\u0430\u0440\u043b\u044b\u049b \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u044f\u043b\u0430\u0440:\n\n',
    noVacancies:     '\u{1F614} \u04d8\u0437\u0456\u0440\u0448\u0435 \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u044f \u0436\u043e\u049b.',
    newVacSeeker:    '\u{1F514} \u0416\u0430\u04a3\u0430 \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u044f!\n\n',
    candidates:      '\u{1F465} \u0421\u0456\u0437\u0433\u0435 \u0441\u0430\u0439 \u043a\u0430\u043d\u0434\u0438\u0434\u0430\u0442\u0442\u0430\u0440:\n\n',
    newApp:          '\u{1F514} \u0416\u0430\u04a3\u0430 \u04e9\u0442\u0456\u043d\u0456\u0448!\n\n\u{1F464} {name}\n\u{1F6E0} {skills}\n\u{1F4DE} {phone}\n\u2B50 {exp}',
    tooFast:         '\u26A0\uFE0F \u0422\u044b\u043c \u0436\u0438\u0456. \u0411\u0456\u0440\u0435\u0440 \u0441\u0435\u043a\u0443\u043d\u0434 \u043a\u04af\u0442\u0456\u04a3\u0456\u0437.',
    exp:             '\u0422\u04d9\u0436\u0456\u0440\u0438\u0431\u0435',
    req:             '\u0422\u0430\u043b\u0430\u043f\u0442\u0430\u0440',
  },
  ru: {
    welcome:         '\u{1F44B} \u041f\u0440\u0438\u0432\u0435\u0442! \u0414\u043e\u0431\u0440\u043e \u043f\u043e\u0436\u0430\u043b\u043e\u0432\u0430\u0442\u044c \u043d\u0430 \u043f\u043b\u0430\u0442\u0444\u043e\u0440\u043c\u0443 \u0442\u0440\u0443\u0434\u0430 \u041c\u0430\u043d\u0433\u0438\u0441\u0442\u0430\u0443!',
    who:             '\u041a\u0442\u043e \u0432\u044b?',
    seeker:          '\u{1F50D} \u0418\u0449\u0443 \u0440\u0430\u0431\u043e\u0442\u0443',
    employer:        '\u{1F4BC} \u0418\u0449\u0443 \u0440\u0430\u0431\u043e\u0442\u043d\u0438\u043a\u0430',
    browse:          '\u{1F4CB} \u041f\u043e\u0441\u043c\u043e\u0442\u0440\u0435\u0442\u044c \u0432\u0441\u0435 \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u0438',
    cancel:          '\u274C \u041e\u0442\u043c\u0435\u043d\u0430',
    cancelled:       '\u274C \u041e\u0442\u043c\u0435\u043d\u0435\u043d\u043e. \u041d\u0430\u0436\u043c\u0438\u0442\u0435 /start.',
    name:            '\u{1F4DD} \u041d\u0430\u043f\u0438\u0448\u0438\u0442\u0435 \u0432\u0430\u0448\u0435 \u0438\u043c\u044f:',
    skills:          '\u{1F6E0} \u041d\u0430\u043f\u0438\u0448\u0438\u0442\u0435 \u043d\u0430\u0432\u044b\u043a\u0438 \u0447\u0435\u0440\u0435\u0437 \u0437\u0430\u043f\u044f\u0442\u0443\u044e:',
    phone:           '\u{1F4DE} \u041d\u0430\u043f\u0438\u0448\u0438\u0442\u0435 \u043d\u043e\u043c\u0435\u0440 \u0442\u0435\u043b\u0435\u0444\u043e\u043d\u0430 (+77001234567):',
    invalidPhone:    '\u26A0\uFE0F \u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u043d\u043e\u043c\u0435\u0440. \u041d\u0430\u043f\u0438\u0448\u0438\u0442\u0435 \u0441\u043d\u043e\u0432\u0430:',
    cityFilter:      '\u{1F4CD} \u0412 \u043a\u0430\u043a\u043e\u043c \u0433\u043e\u0440\u043e\u0434\u0435?\n1. \u0410\u043a\u0442\u0430\u0443\n2. \u0416\u0430\u043d\u0430\u043e\u0437\u0435\u043d\n3. \u0412\u0435\u0437\u0434\u0435',
    districtFilter:  '\u{1F3D8} \u041c\u0438\u043a\u0440\u043e\u0440\u0430\u0439\u043e\u043d (0 - \u043d\u0435\u0432\u0430\u0436\u043d\u043e):',
    scheduleFilter:  '\u{1F554} \u0422\u0438\u043f \u0440\u0430\u0431\u043e\u0442\u044b:\n1. \u041f\u043e\u043b\u043d\u044b\u0439 \u0434\u0435\u043d\u044c\n2. \u0427\u0430\u0441\u0442\u0438\u0447\u043d\u0430\u044f \u0437\u0430\u043d\u044f\u0442\u043e\u0441\u0442\u044c\n3. \u0414\u0440\u0443\u0433\u043e\u0435\n\n0 - \u043d\u0435\u0432\u0430\u0436\u043d\u043e',
    scheduleCustom:  '\u270F\uFE0F \u041d\u0430\u043f\u0438\u0448\u0438\u0442\u0435 \u0441\u0432\u043e\u0439 \u0433\u0440\u0430\u0444\u0438\u043a:',
    expFilter:       '\u2B50 \u0423\u0440\u043e\u0432\u0435\u043d\u044c \u043e\u043f\u044b\u0442\u0430:\n1. Junior\n2. Middle\n3. Senior\n4. \u0412\u0441\u0435',
    saved:           '\u2705 \u0417\u0430\u044f\u0432\u043a\u0430 \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0430!',
    matched:         '\u2705 \u0412\u043e\u0437\u043c\u043e\u0436\u043d\u044b\u0435 \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u0438:\n\n',
    noMatch:         '\u{1F614} \u0412\u0430\u043a\u0430\u043d\u0441\u0438\u0439 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u043e. \u0417\u0430\u044f\u0432\u043a\u0430 \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0430!',
    thinking:        '\u{1F916} AI \u0438\u0449\u0435\u0442...',
    vtitle:          '\u{1F4DD} \u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435 \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u0438:',
    vcompany:        '\u{1F3E2} \u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435 \u043a\u043e\u043c\u043f\u0430\u043d\u0438\u0438:',
    vskills:         '\u{1F6E0} \u041a\u0430\u043a\u0438\u0435 \u043d\u0430\u0432\u044b\u043a\u0438 \u043d\u0443\u0436\u043d\u044b? (\u0447\u0435\u0440\u0435\u0437 \u0437\u0430\u043f\u044f\u0442\u0443\u044e)',
    vcity:           '\u{1F4CD} \u0413\u043e\u0440\u043e\u0434:\n1. \u0410\u043a\u0442\u0430\u0443\n2. \u0416\u0430\u043d\u0430\u043e\u0437\u0435\u043d\n3. \u0412\u0435\u0437\u0434\u0435',
    vdistrict:       '\u{1F3D8} \u041c\u0438\u043a\u0440\u043e\u0440\u0430\u0439\u043e\u043d (0 - \u043d\u0435\u0442):',
    vsalary:         '\u{1F4B0} \u0417\u0430\u0440\u043f\u043b\u0430\u0442\u0430:',
    vschedule:       '\u{1F554} \u0422\u0438\u043f \u0440\u0430\u0431\u043e\u0442\u044b:\n1. \u041f\u043e\u043b\u043d\u044b\u0439 \u0434\u0435\u043d\u044c\n2. \u0427\u0430\u0441\u0442\u0438\u0447\u043d\u0430\u044f \u0437\u0430\u043d\u044f\u0442\u043e\u0441\u0442\u044c\n3. \u0414\u0440\u0443\u0433\u043e\u0435',
    vscheduleCustom: '\u270F\uFE0F \u041d\u0430\u043f\u0438\u0448\u0438\u0442\u0435 \u0441\u0432\u043e\u0439 \u0433\u0440\u0430\u0444\u0438\u043a:',
    vexperience:     '\u2B50 \u041a\u0430\u043a\u043e\u0439 \u043e\u043f\u044b\u0442 \u043d\u0443\u0436\u0435\u043d?\n1. Junior\n2. Middle\n3. Senior\n4. \u0412\u0441\u0435',
    vrequirements:   '\u{1F4CB} \u0422\u0440\u0435\u0431\u043e\u0432\u0430\u043d\u0438\u044f (0 - \u043d\u0435\u0442):',
    vposted:         '\u2705 \u0412\u0430\u043a\u0430\u043d\u0441\u0438\u044f \u043e\u043f\u0443\u0431\u043b\u0438\u043a\u043e\u0432\u0430\u043d\u0430!\n\n',
    allVacancies:    '\u{1F4CB} \u0412\u0441\u0435 \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u0438:\n\n',
    noVacancies:     '\u{1F614} \u0412\u0430\u043a\u0430\u043d\u0441\u0438\u0439 \u043f\u043e\u043a\u0430 \u043d\u0435\u0442.',
    newVacSeeker:    '\u{1F514} \u041d\u043e\u0432\u0430\u044f \u0432\u0430\u043a\u0430\u043d\u0441\u0438\u044f!\n\n',
    candidates:      '\u{1F465} \u041f\u043e\u0434\u0445\u043e\u0434\u044f\u0449\u0438\u0435 \u043a\u0430\u043d\u0434\u0438\u0434\u0430\u0442\u044b:\n\n',
    newApp:          '\u{1F514} \u041d\u043e\u0432\u0430\u044f \u0437\u0430\u044f\u0432\u043a\u0430!\n\n\u{1F464} {name}\n\u{1F6E0} {skills}\n\u{1F4DE} {phone}\n\u2B50 {exp}',
    tooFast:         '\u26A0\uFE0F \u0421\u043b\u0438\u0448\u043a\u043e\u043c \u0431\u044b\u0441\u0442\u0440\u043e. \u041f\u043e\u0434\u043e\u0436\u0434\u0438\u0442\u0435 \u0441\u0435\u043a\u0443\u043d\u0434\u0443.',
    exp:             '\u041e\u043f\u044b\u0442',
    req:             '\u0422\u0440\u0435\u0431\u043e\u0432\u0430\u043d\u0438\u044f',
  },
  en: {
    welcome:         '\u{1F44B} Hello! Welcome to Mangistau Job Platform!',
    who:             'Who are you?',
    seeker:          '\u{1F50D} Looking for a job',
    employer:        '\u{1F4BC} Looking for a worker',
    browse:          '\u{1F4CB} Browse all vacancies',
    cancel:          '\u274C Cancel',
    cancelled:       '\u274C Cancelled. Press /start.',
    name:            '\u{1F4DD} Write your name:',
    skills:          '\u{1F6E0} Write your skills separated by commas:',
    phone:           '\u{1F4DE} Write your phone number (+77001234567):',
    invalidPhone:    '\u26A0\uFE0F Invalid phone. Write again:',
    cityFilter:      '\u{1F4CD} Which city?\n1. Aktau\n2. Zhanaozen\n3. Anywhere',
    districtFilter:  '\u{1F3D8} District (0 if not important):',
    scheduleFilter:  '\u{1F554} Job type:\n1. Full time\n2. Part time\n3. Other\n\n0 - not important',
    scheduleCustom:  '\u270F\uFE0F Write your preferred schedule:',
    expFilter:       '\u2B50 Experience level:\n1. Junior\n2. Middle\n3. Senior\n4. Any',
    saved:           '\u2705 Application saved!',
    matched:         '\u2705 Possible vacancies:\n\n',
    noMatch:         '\u{1F614} No vacancies found. Application saved!',
    thinking:        '\u{1F916} AI is searching...',
    vtitle:          '\u{1F4DD} Write vacancy title:',
    vcompany:        '\u{1F3E2} Write company name:',
    vskills:         '\u{1F6E0} What skills are needed? (comma separated)',
    vcity:           '\u{1F4CD} City:\n1. Aktau\n2. Zhanaozen\n3. Anywhere',
    vdistrict:       '\u{1F3D8} District (0 if none):',
    vsalary:         '\u{1F4B0} Salary:',
    vschedule:       '\u{1F554} Job type:\n1. Full time\n2. Part time\n3. Other',
    vscheduleCustom: '\u270F\uFE0F Write your work schedule:',
    vexperience:     '\u2B50 Experience needed?\n1. Junior\n2. Middle\n3. Senior\n4. Any',
    vrequirements:   '\u{1F4CB} Requirements (0 if none):',
    vposted:         '\u2705 Vacancy published!\n\n',
    allVacancies:    '\u{1F4CB} All vacancies:\n\n',
    noVacancies:     '\u{1F614} No vacancies yet.',
    newVacSeeker:    '\u{1F514} New vacancy!\n\n',
    candidates:      '\u{1F465} Matching candidates:\n\n',
    newApp:          '\u{1F514} New application!\n\n\u{1F464} {name}\n\u{1F6E0} {skills}\n\u{1F4DE} {phone}\n\u2B50 {exp}',
    tooFast:         '\u26A0\uFE0F Too fast. Please wait a second.',
    exp:             'Experience',
    req:             'Requirements',
  },
};

function getLang(chatId) {
  return (userState[chatId] && userState[chatId].lang) || 'ru';
}

function isValidPhone(p) {
  const digits = p.replace(/[\s\-()]/g, '');
  return /^\+?[0-9]{10,13}$/.test(digits);
}

function parseMap(map, text, lang) {
  if (map[lang] && map[lang][text] !== undefined) return map[lang][text];
  return text;
}

function cancelKb(m) {
  return { reply_markup: { keyboard: [[m.cancel]], resize_keyboard: true } };
}

function getCityLabel(lang, key) {
  return (CITY_LABEL[lang] && CITY_LABEL[lang][key]) || '';
}

function getScheduleLabel(lang, key) {
  return (SCHEDULE_LABEL[lang] && SCHEDULE_LABEL[lang][key]) || '';
}

function formatVacancy(v, i, lang) {
  const m = M[lang];
  let msg = i + '. ' + v.title + ' - ' + v.company + '\n';
  msg += v.city;
  if (v.district) msg += ', ' + v.district;
  msg += '\n';
  msg += v.salary + '\n';
  msg += v.type + '\n';
  msg += m.exp + ': ' + v.experience + '\n';
  if (v.requirements) msg += m.req + ': ' + v.requirements + '\n';
  msg += v.phone + '\n\n';
  return msg;
}

function sendLong(bot, chatId, header, items) {
  let msg = header;
  for (let i = 0; i < items.length; i++) {
    if ((msg + items[i]).length > 3800) {
      bot.sendMessage(chatId, msg).catch(function() {});
      msg = items[i];
    } else {
      msg += items[i];
    }
  }
  if (msg.trim()) bot.sendMessage(chatId, msg).catch(function() {});
}

const rateLimiter = new Map();
function isRateLimited(chatId) {
  const now = Date.now();
  const last = rateLimiter.get(chatId) || 0;
  if (now - last < 1000) return true;
  rateLimiter.set(chatId, now);
  return false;
}

setInterval(function() {
  const cutoff = Date.now() - 60000;
  rateLimiter.forEach(function(ts, id) {
    if (ts < cutoff) rateLimiter.delete(id);
  });
}, 600000);

async function skillsMatch(s1, s2) {
  if (!s1 || !s2) return false;
  try {
    const resp = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'user', content: 'Do these skill sets match for a job? Answer only yes or no.\nSkills 1: "' + s1 + '"\nSkills 2: "' + s2 + '"' }],
      max_tokens: 5,
      temperature: 0,
    });
    return resp.choices[0].message.content.trim().toLowerCase().startsWith('yes');
  } catch (e) {
    console.error('OpenAI error:', e.message);
    const a = s1.toLowerCase().split(',').map(function(x) { return x.trim(); }).filter(Boolean);
    const b = s2.toLowerCase().split(',').map(function(x) { return x.trim(); }).filter(Boolean);
    return a.some(function(x) { return b.some(function(y) { return x.includes(y) || y.includes(x); }); });
  }
}

async function filterVacancies(vacancies, state) {
  const results = [];
  for (let i = 0; i < vacancies.length; i++) {
    const v = vacancies[i];
    const match = await skillsMatch(state.skills, v.skills);
    if (!match) continue;
    if (state.cityFilter) {
      if (!v.city || !v.city.toLowerCase().includes(state.cityFilter.toLowerCase())) continue;
    }
    if (state.districtFilter) {
      if (!v.district || !v.district.toLowerCase().includes(state.districtFilter.toLowerCase())) continue;
    }
    if (state.jobTypeFilter) {
      if (!v.type || !v.type.toLowerCase().includes(state.jobTypeFilter.toLowerCase())) continue;
    }
    if (state.experienceFilter) {
      if (!v.experience || !v.experience.toLowerCase().includes(state.experienceFilter.toLowerCase())) continue;
    }
    results.push(v);
  }
  results.sort(function(a, b) {
    const getNum = function(s) { return parseInt((s || '').replace(/\D/g, '') || '0', 10); };
    return getNum(b.salary) - getNum(a.salary);
  });
  return results;
}

function getSkillMatchScore(candidateSkills, vacancySkills) {
  const splitSkills = function(value) {
    return value
      .split(',')
      .map(function(skill) { return skill.trim().toLowerCase(); })
      .filter(Boolean);
  };
  const candidate = splitSkills(candidateSkills);
  const vacancy = splitSkills(vacancySkills);
  if (!candidate.length || !vacancy.length) return 0;

  const matched = candidate.filter(function(skill) {
    return vacancy.some(function(required) {
      return skill === required ||
        (skill.length >= 3 && required.length >= 3 &&
          (skill.includes(required) || required.includes(skill)));
    });
  });
  return Math.round((matched.length / candidate.length) * 100);
}

const matchRequests = new Map();
function isMatchRateLimited(ip) {
  const now = Date.now();
  const recentRequests = (matchRequests.get(ip) || []).filter(function(ts) {
    return now - ts < 60000;
  });
  if (recentRequests.length >= 10) {
    matchRequests.set(ip, recentRequests);
    return true;
  }
  recentRequests.push(now);
  matchRequests.set(ip, recentRequests);
  return false;
}

const vacancyRequests = new Map();
function isVacancyRateLimited(ip) {
  const now = Date.now();
  const recentRequests = (vacancyRequests.get(ip) || []).filter(function(ts) {
    return now - ts < 60 * 60 * 1000;
  });
  if (recentRequests.length >= 5) {
    vacancyRequests.set(ip, recentRequests);
    return true;
  }
  recentRequests.push(now);
  vacancyRequests.set(ip, recentRequests);
  return false;
}

const bot = new TelegramBot(process.env.TELEGRAM_TOKEN, { polling: true });

function showLangMenu(chatId) {
  bot.sendMessage(chatId, 'Choose language / \u0422\u0456\u043b\u0434\u0456 \u0442\u0430\u04a3\u0434\u0430\u04a3\u044b\u0437 / \u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435 \u044f\u0437\u044b\u043a:', {
    reply_markup: {
      keyboard: [['\u{1F1F0}\u{1F1FF} \u049a\u0430\u0437\u0430\u049b\u0448\u0430'], ['\u{1F1F7}\u{1F1FA} \u0420\u0443\u0441\u0441\u043a\u0438\u0439'], ['\u{1F1EC}\u{1F1E7} English']],
      resize_keyboard: true,
    },
  });
}

function showMainMenu(chatId, lang) {
  const m = M[lang];
  bot.sendMessage(chatId, m.welcome + '\n\n' + m.who, {
    reply_markup: { keyboard: [[m.seeker], [m.employer], [m.browse]], resize_keyboard: true },
  });
}

bot.onText(/\/start/, function(msg) {
  delete userState[msg.chat.id];
  showLangMenu(msg.chat.id);
});

bot.onText(/\/cancel/, function(msg) {
  const lang = getLang(msg.chat.id);
  delete userState[msg.chat.id];
  bot.sendMessage(msg.chat.id, M[lang].cancelled);
});

bot.on('message', async function(msg) {
  const chatId = msg.chat.id;
  const text = (msg.text || '').trim();
  if (!text || text.startsWith('/')) return;

  if (isRateLimited(chatId)) {
    bot.sendMessage(chatId, M[getLang(chatId)].tooFast);
    return;
  }

  if (text === '\u{1F1F0}\u{1F1FF} \u049a\u0430\u0437\u0430\u049b\u0448\u0430') { userState[chatId] = { lang: 'kz' }; showMainMenu(chatId, 'kz'); return; }
  if (text === '\u{1F1F7}\u{1F1FA} \u0420\u0443\u0441\u0441\u043a\u0438\u0439')  { userState[chatId] = { lang: 'ru' }; showMainMenu(chatId, 'ru'); return; }
  if (text === '\u{1F1EC}\u{1F1E7} English')  { userState[chatId] = { lang: 'en' }; showMainMenu(chatId, 'en'); return; }

  const state = userState[chatId];
  if (!state || !state.lang) { showLangMenu(chatId); return; }
  const lang = state.lang;
  const m = M[lang];

  if (text === m.cancel) {
    delete userState[chatId];
    bot.sendMessage(chatId, m.cancelled);
    return;
  }

  if (text === m.browse) {
    const list = db.prepare('SELECT * FROM vacancies ORDER BY id DESC').all();
    if (!list.length) { bot.sendMessage(chatId, m.noVacancies); return; }
    sendLong(bot, chatId, m.allVacancies, list.map(function(v, i) { return formatVacancy(v, i + 1, lang); }));
    return;
  }

  if (text === m.seeker) {
    userState[chatId] = { lang: lang, role: 'seeker', step: 'name' };
    bot.sendMessage(chatId, m.name, cancelKb(m));
    return;
  }
  if (text === m.employer) {
    userState[chatId] = { lang: lang, role: 'employer', step: 'title' };
    bot.sendMessage(chatId, m.vtitle, cancelKb(m));
    return;
  }

  if (state.role === 'seeker')   { await seekerFlow(chatId, text, state, m);   return; }
  if (state.role === 'employer') { await employerFlow(chatId, text, state, m); return; }
});

async function seekerFlow(chatId, text, state, m) {
  const lang = state.lang;

  if (state.step === 'name') {
    state.name = text;
    state.step = 'skills';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.skills, cancelKb(m));

  } else if (state.step === 'skills') {
    state.skills = text;
    state.step = 'cityFilter';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.cityFilter, cancelKb(m));

  } else if (state.step === 'cityFilter') {
    const cityCode = parseMap(CITIES, text, lang);
    state.cityFilter = ANY_CITY.has(cityCode) ? null : getCityLabel(lang, text);
    state.step = 'districtFilter';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.districtFilter, cancelKb(m));

  } else if (state.step === 'districtFilter') {
    state.districtFilter = text === '0' ? null : text;
    state.step = 'scheduleFilter';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.scheduleFilter, cancelKb(m));

  } else if (state.step === 'scheduleFilter') {
    if (text === '0') {
      state.jobTypeFilter = null;
    } else if (text === '3') {
      state.step = 'scheduleCustom';
      userState[chatId] = state;
      bot.sendMessage(chatId, m.scheduleCustom, cancelKb(m));
      return;
    } else if (text === '1' || text === '2') {
      state.jobTypeFilter = getScheduleLabel(lang, text);
    } else {
      state.jobTypeFilter = text;
    }
    state.step = 'expFilter';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.expFilter, cancelKb(m));

  } else if (state.step === 'scheduleCustom') {
    state.jobTypeFilter = text;
    state.step = 'expFilter';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.expFilter, cancelKb(m));

  } else if (state.step === 'expFilter') {
    const expCode = parseMap(EXPERIENCE, text, lang);
    state.experienceFilter = ANY_EXP.has(expCode) ? null : expCode;
    state.step = 'phone';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.phone, cancelKb(m));

  } else if (state.step === 'phone') {
    if (!isValidPhone(text)) {
      bot.sendMessage(chatId, m.invalidPhone, cancelKb(m));
      return;
    }
    state.phone = text;
    bot.sendMessage(chatId, m.thinking);

    let vacancies = [];
    try {
      const list = db.prepare('SELECT * FROM vacancies ORDER BY id DESC').all();
      vacancies = await filterVacancies(list, state);
    } catch (e) {
      console.error('filterVacancies error:', e);
    }

    db.prepare('INSERT INTO applications (vacancy_id, name, skills, phone, chat_id, city, district, experience, jobtype) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      vacancies.length > 0 ? vacancies[0].id : 0,
      state.name, state.skills, state.phone, chatId.toString(),
      state.cityFilter || null, state.districtFilter || null,
      state.experienceFilter || null, state.jobTypeFilter || null
    );

    if (vacancies.length > 0) {
      sendLong(bot, chatId, m.matched, vacancies.map(function(v, i) { return formatVacancy(v, i + 1, lang); }));
      vacancies.forEach(function(v) {
        if (v.employer_chat_id && v.employer_chat_id !== chatId.toString()) {
          const notify = m.newApp
            .replace('{name}', state.name)
            .replace('{skills}', state.skills)
            .replace('{phone}', state.phone)
            .replace('{exp}', state.experienceFilter || '-');
          bot.sendMessage(v.employer_chat_id, notify).catch(function() {});
        }
      });
    } else {
      bot.sendMessage(chatId, m.noMatch);
    }
    delete userState[chatId];
  }
}

async function employerFlow(chatId, text, state, m) {
  const lang = state.lang;

  if (state.step === 'title') {
    state.title = text;
    state.step = 'company';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vcompany, cancelKb(m));

  } else if (state.step === 'company') {
    state.company = text;
    state.step = 'skills';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vskills, cancelKb(m));

  } else if (state.step === 'skills') {
    state.skills = text;
    state.step = 'city';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vcity, cancelKb(m));

  } else if (state.step === 'city') {
    const cityCode = parseMap(CITIES, text, lang);
    if (ANY_CITY.has(cityCode)) {
      state.city = lang === 'kz' ? 'Aktau/Zhanaozen' : lang === 'ru' ? 'Aktau/Zhanaozen' : 'Aktau/Zhanaozen';
    } else {
      state.city = getCityLabel(lang, text) || text;
    }
    state.step = 'district';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vdistrict, cancelKb(m));

  } else if (state.step === 'district') {
    state.district = text === '0' ? null : text;
    state.step = 'salary';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vsalary, cancelKb(m));

  } else if (state.step === 'salary') {
    state.salary = text;
    state.step = 'schedule';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vschedule, cancelKb(m));

  } else if (state.step === 'schedule') {
    if (text === '3') {
      state.step = 'scheduleCustom';
      userState[chatId] = state;
      bot.sendMessage(chatId, m.vscheduleCustom, cancelKb(m));
      return;
    } else if (text === '1' || text === '2') {
      state.schedule = getScheduleLabel(lang, text);
    } else {
      state.schedule = text;
    }
    state.step = 'experience';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vexperience, cancelKb(m));

  } else if (state.step === 'scheduleCustom') {
    state.schedule = text;
    state.step = 'experience';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vexperience, cancelKb(m));

  } else if (state.step === 'experience') {
    state.experience = parseMap(EXPERIENCE, text, lang);
    if (ANY_EXP.has(state.experience)) state.experience = 'Any';
    state.step = 'requirements';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.vrequirements, cancelKb(m));

  } else if (state.step === 'requirements') {
    state.requirements = text === '0' ? null : text;
    state.step = 'phone';
    userState[chatId] = state;
    bot.sendMessage(chatId, m.phone, cancelKb(m));

  } else if (state.step === 'phone') {
    if (!isValidPhone(text)) {
      bot.sendMessage(chatId, m.invalidPhone, cancelKb(m));
      return;
    }
    state.phone = text;

    db.prepare('INSERT INTO vacancies (title, company, skills, city, district, type, experience, employer_chat_id, salary, phone, requirements) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      state.title, state.company, state.skills,
      state.city, state.district || null,
      state.schedule, state.experience,
      chatId.toString(),
      state.salary, state.phone,
      state.requirements || null
    );

    const lastVac = db.prepare('SELECT * FROM vacancies WHERE employer_chat_id = ? ORDER BY id DESC LIMIT 1').get(chatId.toString());

    sendLong(bot, chatId, m.vposted, [formatVacancy(lastVac, 1, lang)]);

    const pending = db.prepare('SELECT * FROM applications WHERE vacancy_id = 0').all();
    for (let i = 0; i < pending.length; i++) {
      const app = pending[i];
      if (!app.chat_id || app.chat_id === chatId.toString()) continue;
      try {
        const match = await skillsMatch(app.skills, state.skills);
        if (match) {
          bot.sendMessage(app.chat_id, m.newVacSeeker + formatVacancy(lastVac, 1, lang)).catch(function() {});
        }
      } catch (e) {
        console.error('notify seeker error:', e);
      }
    }

    const allApps = db.prepare('SELECT * FROM applications').all();
    const matched = [];
    for (let i = 0; i < allApps.length; i++) {
      const app = allApps[i];
      if (app.chat_id === chatId.toString()) continue;
      try {
        const match = await skillsMatch(app.skills, state.skills);
        if (match) matched.push(app);
      } catch (e) {
        console.error('match error:', e);
      }
    }

    if (matched.length > 0) {
      let msg = m.candidates;
      matched.forEach(function(app, i) {
        msg += (i + 1) + '. ' + app.name + '\n' + app.skills + '\n' + app.phone + '\n\n';
      });
      bot.sendMessage(chatId, msg).catch(function() {});
    }

    delete userState[chatId];
  }
}

app.post('/api/auth/register', async function(req, res) {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim().toLowerCase() : '';
  const password = req.body?.password;
  if (isAuthRateLimited('register:' + req.ip, 5, 60 * 60 * 1000)) {
    return res.status(429).json({ error: 'Тым көп тіркелу әрекеті. Бір сағаттан кейін қайталап көріңіз.' });
  }
  if (!/^[\p{L}\p{N}_.@+-]{3,64}$/u.test(username)) {
    return res.status(400).json({ error: 'Логин 3–64 таңба болсын. Әріп, сан және . _ @ + - таңбаларын қолдануға болады.' });
  }
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Құпиясөз 8–128 таңбадан тұруы керек.' });
  }

  try {
    const salt = crypto.randomBytes(16);
    const passwordHash = await hashPassword(password, salt);
    const result = db.prepare(
      'INSERT INTO web_users (username, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?)'
    ).run(username, salt.toString('hex'), passwordHash.toString('hex'), Date.now());
    await createWebSession(Number(result.lastInsertRowid), res);
    return res.status(201).json({ user: { id: Number(result.lastInsertRowid), username, role: null } });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Бұл логин бос емес. Басқа логин таңдаңыз.' });
    }
    console.error('web registration error:', error);
    return res.status(500).json({ error: 'Тіркелу сәтсіз аяқталды.' });
  }
});

app.post('/api/auth/login', async function(req, res) {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim().toLowerCase() : '';
  const password = req.body?.password;
  if (isAuthRateLimited('login:' + req.ip, 10, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Тым көп кіру әрекеті. 15 минуттан кейін қайталап көріңіз.' });
  }
  if (!/^[\p{L}\p{N}_.@+-]{3,64}$/u.test(username) ||
      typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Логин немесе құпиясөз дұрыс емес.' });
  }

  try {
    const user = db.prepare(
      'SELECT id, username, password_salt, password_hash, role FROM web_users WHERE username = ?'
    ).get(username);
    const salt = user ? Buffer.from(user.password_salt, 'hex') : Buffer.alloc(16);
    const actualHash = await hashPassword(password, salt);
    const expectedHash = user ? Buffer.from(user.password_hash, 'hex') : Buffer.alloc(64);
    if (!user || actualHash.length !== expectedHash.length ||
        !crypto.timingSafeEqual(actualHash, expectedHash)) {
      return res.status(401).json({ error: 'Логин немесе құпиясөз дұрыс емес.' });
    }
    await createWebSession(user.id, res);
    return res.json({ user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    console.error('web login error:', error);
    return res.status(500).json({ error: 'Жүйеге кіру сәтсіз аяқталды.' });
  }
});

app.get('/api/auth/me', function(req, res) {
  const user = getRequestUser(req);
  return res.json({
    user: user ? { id: user.id, username: user.username, role: user.role } : null,
  });
});

app.post('/api/auth/role', function(req, res) {
  const user = getRequestUser(req);
  if (!user) return res.status(401).json({ error: 'Алдымен тіркеліңіз немесе жүйеге кіріңіз.' });
  if (user.role) return res.status(409).json({ error: 'Тіркелгі рөлі бұрын таңдалған.' });
  const role = req.body?.role;
  if (role !== 'employer' && role !== 'seeker') {
    return res.status(400).json({ error: 'Жұмыс беруші немесе жұмыс іздеуші рөлін таңдаңыз.' });
  }
  const result = db.prepare('UPDATE web_users SET role = ? WHERE id = ? AND role IS NULL')
    .run(role, user.id);
  if (result.changes !== 1) {
    return res.status(409).json({ error: 'Тіркелгі рөлін сақтау мүмкін болмады. Бетіңізді жаңартыңыз.' });
  }
  return res.json({ user: { id: user.id, username: user.username, role } });
});

app.post('/api/auth/logout', function(req, res) {
  const token = getRequestSessionToken(req);
  if (token) {
    db.prepare('DELETE FROM web_sessions WHERE token_hash = ?')
      .run(crypto.createHash('sha256').update(token).digest('hex'));
  }
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.post('/api/matches', async function(req, res) {
  const user = requireRole(req, res, 'seeker');
  if (!user) return;
  const skills = req.body && req.body.skills;
  const city = req.body && req.body.city;

  if (typeof skills !== 'string' || skills.trim().length < 2 || skills.length > 500) {
    return res.status(400).json({ error: 'skills must be a string between 2 and 500 characters.' });
  }
  if (city !== undefined && (typeof city !== 'string' || city.length > 80)) {
    return res.status(400).json({ error: 'city must be a string of at most 80 characters.' });
  }
  if (isMatchRateLimited(req.ip)) {
    return res.status(429).json({ error: 'Too many requests. Please try again in a minute.' });
  }

  try {
    let vacancies = db.prepare(
      'SELECT id, title, company, skills, city, district, type, experience, salary, phone, requirements ' +
      'FROM vacancies ORDER BY id DESC LIMIT 50'
    ).all();
    if (city && city.trim()) {
      const cityFilter = city.trim().toLowerCase();
      vacancies = vacancies.filter(function(vacancy) {
        return (vacancy.city || '').toLowerCase().includes(cityFilter);
      });
    }

    const matches = vacancies
      .map(function(vacancy) {
        return {
          id: vacancy.id,
          title: vacancy.title,
          company: vacancy.company,
          skills: vacancy.skills,
          city: vacancy.city,
          district: vacancy.district,
          type: vacancy.type,
          experience: vacancy.experience,
          salary: vacancy.salary,
          phone: vacancy.phone,
          requirements: vacancy.requirements,
          matchScore: getSkillMatchScore(skills.trim(), vacancy.skills || ''),
        };
      })
      .filter(function(vacancy) { return vacancy.matchScore > 0; })
      .sort(function(a, b) {
      return b.matchScore - a.matchScore || b.id - a.id;
      })
      .slice(0, 10);
    return res.json({ matches });
  } catch (error) {
    console.error('vacancy matching error:', error);
    return res.status(500).json({ error: 'Could not find matching vacancies.' });
  }
});

app.post('/api/vacancies', function(req, res) {
  const user = requireRole(req, res, 'employer');
  if (!user) return;
  const body = req.body || {};
  const fields = ['title', 'company', 'skills', 'city', 'phone'];
  const limits = { title: 120, company: 120, skills: 500, city: 80, phone: 30 };
  const vacancy = {};

  for (const field of fields) {
    if (typeof body[field] !== 'string' || !body[field].trim() ||
        body[field].trim().length > limits[field]) {
      return res.status(400).json({
        error: field + ' is required and must be at most ' + limits[field] + ' characters.',
      });
    }
    vacancy[field] = body[field].trim();
  }
  if (!isValidPhone(vacancy.phone)) {
    return res.status(400).json({ error: 'Телефон нөмірін дұрыс енгізіңіз, мысалы: +77001234567.' });
  }

  const optionalFields = {
    district: 80,
    type: 80,
    experience: 40,
    salary: 80,
    requirements: 1000,
  };
  for (const [field, limit] of Object.entries(optionalFields)) {
    if (body[field] !== undefined &&
        (typeof body[field] !== 'string' || body[field].trim().length > limit)) {
      return res.status(400).json({
        error: field + ' must be a string of at most ' + limit + ' characters.',
      });
    }
    vacancy[field] = typeof body[field] === 'string' ? body[field].trim() : '';
  }

  if (isVacancyRateLimited(req.ip)) {
    return res.status(429).json({ error: 'Вакансияны сағатына 5 реттен артық қоса алмайсыз.' });
  }

  try {
    const result = db.prepare(
      'INSERT INTO vacancies (title, company, skills, city, district, type, experience, employer_chat_id, salary, phone, requirements) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)'
    ).run(
      vacancy.title,
      vacancy.company,
      vacancy.skills,
      vacancy.city,
      vacancy.district || null,
      vacancy.type || null,
      vacancy.experience || null,
      vacancy.salary || null,
      vacancy.phone,
      vacancy.requirements || null
    );
    return res.status(201).json({ id: Number(result.lastInsertRowid), message: 'Вакансия жарияланды.' });
  } catch (error) {
    console.error('vacancy creation error:', error);
    return res.status(500).json({ error: 'Вакансияны сақтау мүмкін болмады.' });
  }
});

app.get('/vacancies', function(req, res) {
  const user = requireRole(req, res);
  if (!user) return;
  res.json(db.prepare(
    'SELECT id, title, company, skills, city, district, type, experience, salary, ' +
    (user.role === 'seeker' ? 'phone' : 'NULL AS phone') + ', requirements ' +
    'FROM vacancies ORDER BY id DESC'
  ).all());
});
app.get('/applications', function(req, res) {
  const adminApiKey = process.env.ADMIN_API_KEY;
  const authorization = req.get('authorization') || '';
  const suppliedKey = Buffer.from(authorization.startsWith('Bearer ') ? authorization.slice(7) : '');
  const expectedKey = Buffer.from(adminApiKey || '');
  if (!adminApiKey || suppliedKey.length !== expectedKey.length ||
      !crypto.timingSafeEqual(suppliedKey, expectedKey)) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  res.json(db.prepare('SELECT * FROM applications ORDER BY id DESC').all());
});
app.get('/health', function(req, res) { res.json({ status: 'ok' }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() { console.log('Server started on port ' + PORT); });