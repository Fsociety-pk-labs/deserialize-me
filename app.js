require('dotenv').config();
const express = require('express');
const path = require('path');
const yaml = require('js-yaml');

const app = express();

app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Main vulnerable app
app.get('/', (req, res) => {
  res.render('index', {
    title: 'fsociety - System Access'
  });
});

// Vulnerable YAML endpoint - THE CHALLENGE
app.get('/api/system-config', (req, res) => {
  const data = req.query.data;
  
  if (!data) {
    return res.json({
      status: 'error',
      message: 'No configuration data provided'
    });
  }
  
  try {
    // UNSAFE YAML parsing - This is the vulnerability!
    const config = yaml.load(data);
    
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

// Admin panel - contains flag (from .env)
app.get('/admin/dashboard', (req, res) => {
  res.json({
    user: 'admin',
    status: 'System Compromised',
    flag: process.env.FLAG || 'FLAG_NOT_SET',
    system_info: 'Node.js v18.x with vulnerable js-yaml',
    data_exfil: true
  });
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`fsociety System Online on http://localhost:${process.env.PORT || 3000}`);
});