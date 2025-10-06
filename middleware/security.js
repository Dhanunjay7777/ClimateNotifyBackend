function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  
  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .trim();
}

function deepSanitize(obj) {
  if (obj === null || obj === undefined) return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(item => deepSanitize(item));
  }
  
  if (typeof obj === 'object') {
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        sanitized[key] = deepSanitize(obj[key]);
      }
    }
    return sanitized;
  }
  
  if (typeof obj === 'string') {
    return sanitizeInput(obj);
  }
  
  return obj;
}

function sanitizeBody(req, res, next) {
  if (req.body) {
    req.body = deepSanitize(req.body);
  }
  next();
}

function sanitizeQuery(req, res, next) {
  if (req.query) {
    req.query = deepSanitize(req.query);
  }
  next();
}

function isValidEmail(email) {
  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 6;
}

function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

function containsSQLInjection(input) {
  if (typeof input !== 'string') return false;
  
  const sqlPatterns = [
    /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b)/gi,
    /(\bUNION\b.*\bSELECT\b)/gi,
    /(;|\-\-|\/\*|\*\/)/g,
    /(\bOR\b\s+\d+\s*=\s*\d+)/gi,
    /(\bAND\b\s+\d+\s*=\s*\d+)/gi
  ];
  
  return sqlPatterns.some(pattern => pattern.test(input));
}

function preventSQLInjection(req, res, next) {
  const checkObject = (obj) => {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        if (typeof value === 'string' && containsSQLInjection(value)) {
          return true;
        }
        if (typeof value === 'object' && value !== null) {
          if (checkObject(value)) return true;
        }
      }
    }
    return false;
  };
  
  if (checkObject(req.body) || checkObject(req.query)) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid input detected. Please remove special characters and try again.'
    });
  }
  
  next();
}

function logSuspiciousActivity(req, res, next) {
  const suspiciousPatterns = [
    /<script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /(\bUNION\b.*\bSELECT\b)/gi
  ];
  
  const checkForSuspiciousContent = (obj) => {
    const str = JSON.stringify(obj);
    return suspiciousPatterns.some(pattern => pattern.test(str));
  };
  
  if (checkForSuspiciousContent(req.body) || checkForSuspiciousContent(req.query)) {
    console.warn('⚠️ Suspicious activity detected:', {
      ip: req.ip,
      path: req.path,
      method: req.method,
      timestamp: new Date().toISOString(),
      userAgent: req.get('user-agent')
    });
  }
  
  next();
}

function validateContentType(req, res, next) {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.get('content-type');
    
    if (!contentType || (!contentType.includes('application/json') && !contentType.includes('multipart/form-data'))) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid Content-Type. Expected application/json or multipart/form-data'
      });
    }
  }
  
  next();
}

function sanitizeErrorMessage(error) {
  if (process.env.NODE_ENV === 'production') {
    const safeErrors = {
      'ValidationError': 'Invalid input provided',
      'CastError': 'Invalid data format',
      'MongoError': 'Database operation failed',
      'JsonWebTokenError': 'Authentication failed',
      'TokenExpiredError': 'Session expired'
    };
    
    return safeErrors[error.name] || 'An error occurred. Please try again.';
  }
  
  return error.message || 'An error occurred';
}

function validatePasswordStrength(password) {
  const errors = [];
  
  if (!password || typeof password !== 'string') {
    return { valid: false, errors: ['Password is required'] };
  }
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  const commonPasswords = ['password', '12345678', 'qwerty', 'abc123', 'password123'];
  if (commonPasswords.includes(password.toLowerCase())) {
    errors.push('Password is too common. Please choose a stronger password');
  }
  
  return {
    valid: errors.length === 0,
    errors: errors
  };
}

function validateRequestSize(req, res, next) {
  const contentLength = req.get('content-length');
  const maxSize = 10 * 1024 * 1024;
  
  if (contentLength && parseInt(contentLength) > maxSize) {
    return res.status(413).json({
      status: 'error',
      message: 'Request payload too large. Maximum size is 10MB'
    });
  }
  
  next();
}

function addSecurityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Frame-Options', 'DENY');
  res.removeHeader('X-Powered-By');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  next();
}

function preventNoSQLInjection(req, res, next) {
  const checkNoSQLInjection = (obj) => {
    if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        if (key.startsWith('$') || key.startsWith('_')) {
          return true;
        }
        if (typeof obj[key] === 'object' && checkNoSQLInjection(obj[key])) {
          return true;
        }
      }
    }
    return false;
  };
  
  if (checkNoSQLInjection(req.body) || checkNoSQLInjection(req.query)) {
    console.warn('⚠️ NoSQL injection attempt detected:', {
      ip: req.ip,
      path: req.path,
      timestamp: new Date().toISOString()
    });
    
    return res.status(400).json({
      status: 'error',
      message: 'Invalid request format'
    });
  }
  
  next();
}

function validateEnvironment() {
  const required = [
    'APPWRITE_ENDPOINT',
    'APPWRITE_PROJECT_ID',
    'APPWRITE_API_KEY',
    'APPWRITE_DATABASE_ID',
    'CONSUMERS_COLLECTION_ID',
    'MESSAGES_COLLECTION_ID'
  ];

  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:', missing.join(', '));
    throw new Error(`Missing environment variables: ${missing.join(', ')}`);
  }

  return true;
}

function validateFileUpload(req, res, next) {
  if (req.file || req.files) {
    const file = req.file || (req.files && req.files[0]);
    
    if (file) {
      const maxSize = 10 * 1024 * 1024;
      if (file.size > maxSize) {
        return res.status(413).json({
          status: 'error',
          message: 'File size exceeds 10MB limit'
        });
      }

      const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
      if (file.mimetype && !allowedTypes.includes(file.mimetype)) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid file type. Only PDF and images allowed'
        });
      }
    }
  }
  
  next();
}

module.exports = {
  sanitizeInput,
  deepSanitize,
  sanitizeBody,
  sanitizeQuery,
  isValidEmail,
  isValidPassword,
  isValidUUID,
  containsSQLInjection,
  preventSQLInjection,
  logSuspiciousActivity,
  validateContentType,
  sanitizeErrorMessage,
  validatePasswordStrength,
  validateRequestSize,
  addSecurityHeaders,
  preventNoSQLInjection,
  validateEnvironment,
  validateFileUpload
};
