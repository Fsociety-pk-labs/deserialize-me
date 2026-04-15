require('dotenv').config();
const express = require('express');
const path = require('path');
const yaml = require('js-yaml');
const crypto = require('crypto');

// Custom schema to allow JavaScript execution (UNSAFE)
const dangerousSchema = yaml.DEFAULT_SCHEMA;

const app = express();

app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session storage (in-memory)
const sessions = new Map();
const attempts = new Map();

// Main page
app.get('/', (req, res) => {
  res.render('index', {
    title: 'TechCorp - Enterprise Solutions'
  });
});

// Login endpoint - required to access admin
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Rate limiting - only 5 attempts per IP per 10 minutes
  const ip = req.ip;
  if (!attempts.has(ip)) {
    attempts.set(ip, []);
  }
  
  const timeWindow = Date.now() - 10 * 60 * 1000;
  const recentAttempts = attempts.get(ip).filter(t => t > timeWindow);
  
  if (recentAttempts.length >= 5) {
    return res.status(429).json({
      status: 'error',
      message: 'Too many login attempts. Try again later.'
    });
  }
  
  recentAttempts.push(Date.now());
  attempts.set(ip, recentAttempts);
  
  // Simple credential check - tricky: password is not "admin"
  if (username === 'admin' && password === 'TechCorp2024!') {
    const sessionId = crypto.randomBytes(32).toString('hex');
    sessions.set(sessionId, {
      username: 'admin',
      createdAt: Date.now(),
      ip: ip
    });
    
    return res.json({
      status: 'success',
      message: 'Login successful',
      sessionId: sessionId
    });
  }
  
  res.status(401).json({
    status: 'error',
    message: 'Invalid credentials'
  });
});

// Protected admin endpoint - needs valid session
app.get('/admin/dashboard', (req, res) => {
  const sessionId = req.headers['x-session-id'];
  
  if (!sessionId || !sessions.has(sessionId)) {
    return res.status(401).json({
      status: 'error',
      message: 'Unauthorized. Please login first.'
    });
  }
  
  const session = sessions.get(sessionId);
  
  // Session validation - must be from same IP
  if (session.ip !== req.ip) {
    sessions.delete(sessionId);
    return res.status(401).json({
      status: 'error',
      message: 'Session invalid'
    });
  }
  
  // Sessions expire after 30 minutes
  if (Date.now() - session.createdAt > 30 * 60 * 1000) {
    sessions.delete(sessionId);
    return res.status(401).json({
      status: 'error',
      message: 'Session expired'
    });
  }
  
  return res.json({
    user: session.username,
    status: 'Authorized',
    message: 'You have successfully authenticated',
    hint: 'The FLAG is stored in process.env.FLAG. Use the /api/system-config endpoint with YAML RCE to extract it.'
  });
});

// System config endpoint - VULNERABLE to YAML deserialization RCE
// This is where the FLAG is hidden via code execution
app.post('/api/system-config', (req, res) => {
  const { data } = req.body;
  
  if (!data) {
    return res.status(400).json({
      status: 'error',
      message: 'No configuration data provided'
    });
  }
  
  // Basic input validation - can be bypassed
  if (data.length > 10000) {
    return res.status(413).json({
      status: 'error',
      message: 'Payload too large'
    });
  }
  
  try {
    // UNSAFE: Using DEFAULT_SCHEMA which allows !!js/object and !!js/function
    // This enables arbitrary JavaScript execution through YAML deserialization
    const config = yaml.load(data);
    
    // If the exploit returns a string, return it
    if (typeof config === 'string') {
      return res.json({
        status: 'success',
        result: config,
        message: 'Configuration processed'
      });
    }
    
    // If it's a function, call it and return the result
    if (typeof config === 'function') {
      try {
        const result = config();
        return res.json({
          status: 'success',
          result: result,
          message: 'Function executed'
        });
      } catch (e) {
        return res.json({
          status: 'error',
          message: 'Function execution error: ' + e.message
        });
      }
    }
    
    res.json({
      status: 'success',
      config: config,
      message: 'Configuration loaded'
    });
  } catch (err) {
    res.json({
      status: 'error',
      message: 'Invalid YAML: ' + err.message
    });
  }
});

// Flag retrieval endpoint - hidden in process environment
app.get('/api/system-info', (req, res) => {
  const sessionId = req.headers['x-session-id'];
  
  // Requires authentication
  if (!sessionId || !sessions.has(sessionId)) {
    return res.status(401).json({
      status: 'error',
      message: 'Authentication required'
    });
  }
  
  res.json({
    environment: process.env.NODE_ENV,
    system: 'Node.js',
    version: process.version,
    message: 'System running with environment: ' + process.env.NODE_ENV
  });
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});