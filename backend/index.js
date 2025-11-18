import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

import authRoutes from './routes/auth.js';
import doctorRoutes from './routes/doctors.js';
import appointmentRoutes from './routes/appointments.js';
import notificationRoutes from './routes/notifications.js';

dotenv.config();

const app = express();

// Read allowed origins from .env (comma-separated). Normalize and log for debugging.
const rawAllowed = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const normalize = s => (s || '').replace(/\/+$/, '').toLowerCase();
const allowedOrigins = rawAllowed.map(normalize);

if (allowedOrigins.length === 0) {
  console.warn('ALLOWED_ORIGINS not set in .env — defaulting to http://localhost:5173 for development');
  allowedOrigins.push('http://localhost:5173');
}

console.log('Configured ALLOWED_ORIGINS:', allowedOrigins);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // server-to-server or curl
    const n = normalize(origin);
    if (allowedOrigins.includes(n)) return callback(null, true);

    // Allow common local dev origins (any port) so minor host/port differences don't break dev.
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(n)) {
      console.warn('Allowing localhost origin by pattern:', origin);
      return callback(null, true);
    }

    console.warn('Blocked CORS origin:', origin);
    return callback(null, false);
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

// request logger for debugging
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.originalUrl, 'Origin:', req.headers.origin || '<none>');
  next();
});

// Validate critical environment variables early to avoid confusing runtime errors
if (!process.env.MONGODB_URI) {
  console.error('Missing MONGODB_URI in environment. Please set it in your .env file');
  process.exit(1);
}

if (!process.env.JWT_SECRET) {
  console.error('Missing JWT_SECRET in environment. Please set JWT_SECRET in your .env file');
  process.exit(1);
}

app.use('/api/auth', authRoutes);
app.use('/api/doctors', doctorRoutes);
app.use('/api/appointments', appointmentRoutes);
app.use('/api/notifications', notificationRoutes);

function jwtAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = auth.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = payload;
    next();
  });
}

// protect routes
app.get('/api/protected', jwtAuth, (req, res) => {
  res.json({ user: req.user });
});

// start server only after Mongo connects
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });
