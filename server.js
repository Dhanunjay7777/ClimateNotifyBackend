const sdk = require('node-appwrite');
const fs = require('fs');
const { InputFile } = require('node-appwrite');

async function uploadFileToAppwriteStorage(fileBuffer, filename) {
  const client = new sdk.Client()
    .setEndpoint(process.env.APPWRITE_ENDPOINT)
    .setProject(process.env.APPWRITE_PROJECT_ID)
    .setKey(process.env.APPWRITE_API_KEY);

  const storage = new sdk.Storage(client);
  const bucketId = process.env.APPWRITE_BUCKET_ID; // Bucket ID from environment variables

  try {
    // Create InputFile from buffer
    const inputFile = InputFile.fromBuffer(fileBuffer, filename);

    const response = await storage.createFile(bucketId, sdk.ID.unique(), inputFile);
    const fileId = response.$id;

    // Construct the file URL (view URL)
    const fileUrl = `${process.env.APPWRITE_ENDPOINT}/storage/buckets/${bucketId}/files/${fileId}/view?project=${process.env.APPWRITE_PROJECT_ID}`;
    return { fileId, fileUrl };
  } catch (error) {
    // Log error message only, not full object
    console.error('❌ Appwrite upload error:', error.message || 'Upload failed');
    throw error;
  }
}


const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Client, Databases, ID, Query } = require('node-appwrite');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
require('dotenv').config();

// Import security middleware
const {
  sanitizeBody,
  sanitizeQuery,
  preventSQLInjection,
  logSuspiciousActivity,
  validateContentType,
  isValidEmail,
  isValidPassword,
  sanitizeErrorMessage,
  validatePasswordStrength,
  validateRequestSize,
  addSecurityHeaders,
  preventNoSQLInjection,
  validateEnvironment,
  validateFileUpload
} = require('./middleware/security');

// Validate environment variables at startup
try {
  validateEnvironment();
} catch (error) {
  console.error('Server startup failed:', error.message);
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 5000;

// Trust proxy - Required for apps behind reverse proxies (Render, Heroku, etc.)
// This allows Express to correctly identify client IPs from X-Forwarded-For headers
app.set('trust proxy', 1);

// Initialize Appwrite
const client = new Client()
  .setEndpoint(process.env.APPWRITE_ENDPOINT)
  .setProject(process.env.APPWRITE_PROJECT_ID)
  .setKey(process.env.APPWRITE_API_KEY);

const databases = new Databases(client);

// Initialize Firebase Admin SDK
let firebaseApp;
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    firebaseApp = admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  } else {
  }
} catch (error) {
}

// ===== FCM HELPER FUNCTIONS =====

/**
 * Fetch all active FCM tokens from the tokens collection using direct HTTP
 */
async function getActiveTokens() {
  try {
    if (!process.env.TOKENS_COLLECTION_ID) {
      return [];
    }
    const url = `${process.env.APPWRITE_ENDPOINT}/databases/${process.env.APPWRITE_DATABASE_ID}/collections/${process.env.TOKENS_COLLECTION_ID}/documents`;
    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'X-Appwrite-Project': process.env.APPWRITE_PROJECT_ID,
        'X-Appwrite-Key': process.env.APPWRITE_API_KEY,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    // Filter active tokens and extract fcmToken values
    const tokens = data.documents
      .filter(doc => doc.isActive !== false && doc.fcmToken && doc.fcmToken.trim() !== '')
      .map(doc => doc.fcmToken);


    return tokens;
  } catch (error) {

    return [];
  }
}

/**
 * Send FCM notification to multiple tokens
 */
async function sendFCMNotification(title, body, tokens, data = {}) {
  if (!admin.apps.length) {

    return { success: 0, failure: 0, errors: ['Firebase not configured'] };
  }

  if (!tokens || tokens.length === 0) {

    return { success: 0, failure: 0, errors: ['No tokens available'] };
  }

  try {
    const message = {
      notification: {
        title: title,
        body: body,
      },
      data: {
        timestamp: new Date().toISOString(),
        type: data.type || 'notification',
        messageId: data.messageId || ''
      },
      tokens: tokens
    };



    
    // Use the messaging instance directly
    const messaging = admin.messaging();
    const response = await messaging.sendEachForMulticast(message);
    

    
    // Log any failures for debugging
    if (response.failureCount > 0) {
      response.responses.forEach((resp, idx) => {
        if (!resp.success) {

        }
      });
    }

    return {
      success: response.successCount,
      failure: response.failureCount,
      errors: response.responses
        .filter(resp => !resp.success)
        .map(resp => resp.error?.message || resp.error?.code)
    };

  } catch (error) {


    return {
      success: 0,
      failure: tokens.length,
      errors: [error.message]
    };
  }
}

/**
 * Fetch FCM tokens for specific userIds
 */
async function getTokensByUserIds(userIds) {
  try {
    if (!process.env.TOKENS_COLLECTION_ID || !userIds || userIds.length === 0) {

      return [];
    }


    const url = `${process.env.APPWRITE_ENDPOINT}/databases/${process.env.APPWRITE_DATABASE_ID}/collections/${process.env.TOKENS_COLLECTION_ID}/documents`;
    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'X-Appwrite-Project': process.env.APPWRITE_PROJECT_ID,
        'X-Appwrite-Key': process.env.APPWRITE_API_KEY,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    // Filter tokens for specific userIds and active tokens
    const tokens = data.documents
      .filter(doc => 
        userIds.includes(doc.userId) && 
        doc.isActive !== false && 
        doc.fcmToken && 
        doc.fcmToken.trim() !== ''
      )
      .map(doc => doc.fcmToken);


    return tokens;
  } catch (error) {

    return [];
  }
}

/**
 * Send notification to all active users
 */
async function notifyAllUsers(title, body, data = {}) {
  try {
    const tokens = await getActiveTokens();
    
    if (tokens.length === 0) {

      return { success: 0, failure: 0, errors: ['No active tokens'] };
    }

    return await sendFCMNotification(title, body, tokens, data);
  } catch (error) {

    return { success: 0, failure: 0, errors: [error.message] };
  }
}

async function notifySpecificUsers(userIds, title, body, data = {}) {
  try {
    const tokens = await getTokensByUserIds(userIds);
    
    if (tokens.length === 0) {

      return { success: 0, failure: 0, errors: ['No tokens for selected users'] };
    }

    return await sendFCMNotification(title, body, tokens, data);
  } catch (error) {

    return { success: 0, failure: 0, errors: [error.message] };
  }
}

// ===== RENDER API HELPER FUNCTIONS =====

/**
 * Check if user has admin access level
 */
async function verifyAdminAccess(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Authentication required. Admin access only.');
  }

  // Extract user ID from Bearer token
  const userId = authHeader.replace('Bearer ', '');
  
  if (!userId || userId === 'admin-token') {
    throw new Error('Invalid authentication token. Please login again.');
  }

  try {
    // Get user from database to check accessLevel using consumerID
    const user = await findUserByConsumerID(userId);

    // Check if user has admin access
    if (!user) {
      throw new Error(`User with consumerID '${userId}' not found in database. Please ensure you are logged in and your account exists.`);
    }
    
    if (user.accessLevel !== 'admin') {
      throw new Error(`Access denied. Current access level: '${user.accessLevel}', required: 'admin'. Contact administrator to update your access level in the consumers collection.`);
    }

    // Check if user is approved
    if (user.approvedStatus !== 'true' && user.approvedStatus !== true) {
      throw new Error('Account not approved. Contact administrator.');
    }

    return true;
  } catch (error) {
    throw new Error(error.message || 'Authentication failed. Admin access required.');
  }
}

/**
 * Make authenticated request to Render API
 */
async function makeRenderAPIRequest(method, endpoint, data = null) {
  const renderApiKey = process.env.RENDER_API_KEY;
  
  if (!renderApiKey) {
    throw new Error('RENDER_API_KEY environment variable is required');
  }

  const config = {
    method: method,
    url: `https://api.render.com/v1${endpoint}`,
    headers: {
      'Accept': 'application/json',
      'Authorization': `Bearer ${renderApiKey}`
    },
    timeout: 30000
  };

  if (data && (method === 'POST' || method === 'PATCH' || method === 'PUT')) {
    config.data = data;
    config.headers['Content-Type'] = 'application/json';
  }

  try {
    const response = await axios(config);
    return response.data;
  } catch (error) {
    // Log error details server-side only
    if (process.env.NODE_ENV === 'development') {
      console.error('Render API Error:', {
        status: error.response?.status,
        message: error.response?.data?.message || error.message,
        endpoint: endpoint
      });
    } else {
      console.error('Render API Error:', error.response?.status || 'Request failed');
    }
    throw new Error('Render API request failed');
  }
}

// ===== USER VALIDATION HELPER FUNCTIONS =====

// Check if email already exists in the database
async function checkEmailExists(email) {
  try {
    const existingUsers = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.CONSUMERS_COLLECTION_ID || 'consumers',
      [Query.equal('email', email.toLowerCase().trim())]
    );
    
    const exists = existingUsers.documents.length > 0;
    if (exists) {

    } else {

    }
    
    return exists;
  } catch (error) {

    return false; // Assume email doesn't exist if check fails
  }
}

// Check if consumerID already exists in the database
async function checkConsumerIdExists(consumerID) {
  try {
    const existingConsumers = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.CONSUMERS_COLLECTION_ID || 'consumers',
      [Query.equal('consumerID', consumerID)]
    );
    return existingConsumers.documents.length > 0;
  } catch (error) {

    return false; // Assume consumerID doesn't exist if check fails
  }
}

// Find user by consumerID using direct API (SDK has issues with Query)
async function findUserByConsumerID(consumerID) {
  try {
    // Use direct API call to avoid SDK Query issues
    const databaseId = process.env.APPWRITE_DATABASE_ID;
    const collectionId = process.env.CONSUMERS_COLLECTION_ID || 'consumers';
    const projectId = process.env.APPWRITE_PROJECT_ID;
    const apiKey = process.env.APPWRITE_API_KEY;
    const endpoint = process.env.APPWRITE_ENDPOINT;

    const fullUrl = `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents`;

    const response = await fetch(fullUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Appwrite-Project': projectId,
        'X-Appwrite-Key': apiKey
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    
    // Find user with matching consumerID
    if (data.documents && data.documents.length > 0) {
      const user = data.documents.find(doc => doc.consumerID === consumerID);
      return user || null;
    }
    return null;
  } catch (error) {
    return null;
  }
}

// Generate a unique consumerID with collision checking
async function generateUniqueConsumerID() {
  let consumerID = uuidv4();
  let attempts = 0;
  const maxAttempts = 10;



  while (attempts < maxAttempts) {
    const exists = await checkConsumerIdExists(consumerID);
    if (!exists) {

      return consumerID; // Found a unique ID
    }
    
    consumerID = uuidv4(); // Generate new UUID
    attempts++;

  }


  throw new Error('Unable to generate unique consumer ID after multiple attempts');
}

// Middleware

// Enhanced Helmet Security Configuration
app.use(helmet({
  // Content Security Policy - controls which resources can be loaded
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for React
      scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts for React
      imgSrc: ["'self'", "data:", "https:", "blob:"], // Allow images from various sources
      connectSrc: [
        "'self'",
        process.env.APPWRITE_ENDPOINT || "https://cloud.appwrite.io",
        "https://api.render.com",
        "https://fcm.googleapis.com",
        process.env.CLIENT_URL || "http://localhost:5173"
      ],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'", "blob:"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  
  // Cross-Origin-Embedder-Policy - controls what resources can be embedded
  crossOriginEmbedderPolicy: false, // Disabled to allow external resources
  
  // Cross-Origin-Opener-Policy - isolates browsing context
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  
  // Cross-Origin-Resource-Policy - controls who can load resources
  crossOriginResourcePolicy: { policy: "cross-origin" },
  
  dnsPrefetchControl: { allow: true },
  
  expectCt: {
    enforce: true,
    maxAge: 30
  },
  
  frameguard: { action: 'deny' },
  
  hidePoweredBy: true,
  
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  
  ieNoOpen: true,
  
  noSniff: true,
  
  originAgentCluster: true,
  
  permittedCrossDomainPolicies: { permittedPolicies: "none" },
  
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  
  xssFilter: true
}));

app.use(compression());

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 86400
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const limiter = rateLimit({
  windowMs: (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX_REQUESTS || 100,
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: false,
  message: {
    status: 'error',
    message: 'Too many authentication attempts. Please try again after 15 minutes.'
  }
});

const fileUploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  skipSuccessfulRequests: false,
  message: {
    status: 'error',
    message: 'Too many file uploads. Please try again after 1 hour.'
  }
});

app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);

app.use(addSecurityHeaders);
app.use(validateRequestSize);
app.use(logSuspiciousActivity);
app.use(sanitizeQuery);
app.use(sanitizeBody);
app.use(preventSQLInjection);
app.use(preventNoSQLInjection);
app.use(validateContentType);


app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {}
  };

  try {
    await databases.list();
    health.services.appwrite = 'healthy';
  } catch (error) {
    health.services.appwrite = 'unhealthy';
    health.status = 'degraded';
    if (process.env.NODE_ENV === 'development') {
      console.error('Health check - Appwrite error:', error.message);
    }
  }

  try {
    if (firebaseApp) {
      await admin.messaging().send({
        topic: 'health-check-topic',
        notification: { title: 'test', body: 'test' }
      }, true);
      health.services.firebase = 'healthy';
    } else {
      health.services.firebase = 'not_configured';
    }
  } catch (error) {
    if (error.code === 'messaging/invalid-argument' || error.code === 'messaging/registration-token-not-registered') {
      health.services.firebase = 'healthy';
    } else {
      health.services.firebase = 'unhealthy';
      health.status = 'degraded';
      if (process.env.NODE_ENV === 'development') {
        console.error('Health check - Firebase error:', error.message);
      }
    }
  }

  if (health.status === 'degraded') {
    return res.status(503).json(health);
  }

  res.json(health);
});

// Legacy health check (kept for backward compatibility)
app.get('/health-simple', async (req, res) => {
  try {
    await databases.list();
    res.json({
      status: 'success',
      message: 'Server is running',
    });
  } catch (error) {
    if (process.env.NODE_ENV === 'development') {
      console.error('Health check - Appwrite connection error:', error.message);
    }
    res.status(500).json({ 
      status: 'error', 
      message: 'Service temporarily unavailable'
    });
  }
});

// ===== USER AUTHENTICATION ENDPOINTS =====

// User Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { fullname, email, password, agreeTerms } = req.body;

    // Validation
    if (!fullname || !email || !password || agreeTerms === undefined) {
      return res.status(400).json({
        status: 'error',
        message: 'All fields are required: fullname, email, password, agreeTerms'
      });
    }

    if (fullname.trim().length < 2) {
      return res.status(400).json({
        status: 'error',
        message: 'Full name must be at least 2 characters long'
      });
    }

    // Enhanced email validation using security middleware
    if (!isValidEmail(email)) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide a valid email address'
      });
    }

    // Enhanced password validation with strength requirements
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        status: 'error',
        message: 'Password does not meet security requirements',
        errors: passwordValidation.errors
      });
    }

    // Legacy check for backwards compatibility (minimum 6 characters)
    if (password.length < 6) {
      return res.status(400).json({
        status: 'error',
        message: 'Password must be at least 6 characters long'
      });
    }

    if (agreeTerms !== true) {
      return res.status(400).json({
        status: 'error',
        message: 'You must agree to the terms and conditions'
      });
    }

    // Check if email already exists
    const emailExists = await checkEmailExists(email);
    if (emailExists) {
      return res.status(400).json({
        status: 'error',
        message: 'An account with this email already exists'
      });
    }

    // Generate unique ConsumerID
    let consumerID;
    try {
      consumerID = await generateUniqueConsumerID();
    } catch (error) {
      return res.status(500).json({
        status: 'error',
        message: 'Unable to generate unique consumer ID. Please try again.'
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);




    // Create consumer document
    const consumerData = {
      consumerID: String(consumerID),
      fullname: String(fullname.trim()),
      email: String(email.toLowerCase().trim()),
      password: String(hashedPassword),
      agreeTerms: String(agreeTerms ? 'true' : 'false'), // Convert boolean to string
      accessLevel: String('user'), // Default access level
      approvedStatus: String('false'), // Convert boolean to string
      CreatedAt: String(new Date().toISOString()), // Capital C to match Appwrite schema
      lastLogin: String('') // Use empty string instead of null for string fields
    };
    try {
      const newConsumer = await databases.createDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.CONSUMERS_COLLECTION_ID || 'consumers',
        ID.unique(),
        consumerData
      );







      // Return success response (don't send password back)
      res.status(201).json({
        status: 'success',
        message: 'Account created successfully! Please wait for admin approval.',
        data: {
          id: newConsumer.$id,
          consumerID: consumerID,
          fullname: newConsumer.fullname,
          email: newConsumer.email,
          accessLevel: newConsumer.accessLevel,
          approvedStatus: newConsumer.approvedStatus,
          agreeTerms: newConsumer.agreeTerms,
          createdAt: newConsumer.CreatedAt || newConsumer.$createdAt // Use CreatedAt or fallback to $createdAt
        }
      });

    } catch (createError) {

      
      // Check if it's a unique constraint violation (409 error)
      if (createError.code === 409 || createError.type === 'document_already_exists') {
        return res.status(409).json({
          status: 'error',
          message: 'User already exists with this email or consumer ID',
          error: 'duplicate_user'
        });
      }
      
      // Re-throw other errors to be handled by outer catch block
      throw createError;
    }

  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to create account',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Admin Create User
app.post('/api/admin/create-user', async (req, res) => {
  try {
    // Admin authentication check
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication required. Admin access only.'
      });
    }

    const { fullname, email, password, role, approvedStatus, agreeTerms } = req.body;
    // Validation
    if (!fullname || !email || !password || !role || approvedStatus === undefined) {
      return res.status(400).json({
        status: 'error',
        message: 'All fields are required: fullname, email, password, role, approvedStatus'
      });
    }

    if (fullname.trim().length < 2) {
      return res.status(400).json({
        status: 'error',
        message: 'Full name must be at least 2 characters long'
      });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide a valid email address'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        status: 'error',
        message: 'Password must be at least 6 characters long'
      });
    }

    // Check if email already exists
    const emailExists = await checkEmailExists(email);
    if (emailExists) {
      return res.status(400).json({
        status: 'error',
        message: 'An account with this email already exists'
      });
    }

    // Generate unique consumer ID
    let consumerID;
    try {
      consumerID = await generateUniqueConsumerID();
    } catch (error) {
      return res.status(500).json({
        status: 'error',
        message: 'Unable to generate unique consumer ID. Please try again.'
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create consumer document with admin-specified values
    const consumerData = {
      consumerID: String(consumerID),
      fullname: String(fullname.trim()),
      email: String(email.toLowerCase().trim()),
      password: String(hashedPassword),
      agreeTerms: String(agreeTerms !== undefined ? agreeTerms : 'true'),
      accessLevel: String(role), // Use the role specified by admin
      approvedStatus: String(approvedStatus), // Use the approval status specified by admin
      CreatedAt: String(new Date().toISOString()),
      lastLogin: String('')
    };
    try {
      const newConsumer = await databases.createDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.CONSUMERS_COLLECTION_ID || 'consumers',
        ID.unique(),
        consumerData
      );







      // Return success response (don't send password back)
      res.status(201).json({
        status: 'success',
        message: 'User created successfully by admin.',
        data: {
          id: newConsumer.$id,
          consumerID: consumerID,
          fullname: newConsumer.fullname,
          email: newConsumer.email,
          accessLevel: newConsumer.accessLevel,
          approvedStatus: newConsumer.approvedStatus,
          agreeTerms: newConsumer.agreeTerms,
          createdAt: newConsumer.CreatedAt || newConsumer.$createdAt
        }
      });

    } catch (createError) {

      
      // Check if it's a unique constraint violation (409 error)
      if (createError.code === 409 || createError.type === 'document_already_exists') {
        return res.status(409).json({
          status: 'error',
          message: 'User already exists with this email or consumer ID',
          error: 'duplicate_user'
        });
      }
      
      // Re-throw other errors to be handled by outer catch block
      throw createError;
    }

  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to create user',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Email and password are required'
      });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide a valid email address'
      });
    }

    // Find user by email - try SDK first, fallback to direct API
    try {
      let user = null;
      
      // Method 1: Try using SDK with Query (preferred if it works)
      try {
        const users = await databases.listDocuments(
          process.env.APPWRITE_DATABASE_ID,
          process.env.CONSUMERS_COLLECTION_ID || 'consumers',
          [Query.equal('email', email.toLowerCase().trim())]
        );
        
        if (users.documents && users.documents.length > 0) {
          user = users.documents[0];
        }
      } catch (sdkError) {
        
        // Method 2: Direct API call - get all and filter manually
        const databaseId = process.env.APPWRITE_DATABASE_ID;
        const collectionId = process.env.CONSUMERS_COLLECTION_ID || 'consumers';
        const projectId = process.env.APPWRITE_PROJECT_ID;
        const apiKey = process.env.APPWRITE_API_KEY;
        const endpoint = process.env.APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1';

        const fullUrl = `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents`;

        const response = await fetch(fullUrl, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'X-Appwrite-Project': projectId,
            'X-Appwrite-Key': apiKey
          }
        });

        if (!response.ok) {
          const errorData = await response.text();
          throw new Error(`Direct API error: ${response.status}`);
        }

        const allUsers = await response.json();

        // Filter users by email manually
        const matchingUsers = allUsers.documents?.filter(doc => 
          doc.email && doc.email.toLowerCase() === email.toLowerCase().trim()
        ) || [];
        
        if (matchingUsers.length > 0) {
          user = matchingUsers[0];
        }
      }

      // Check if user was found by either method
      if (!user) {
        return res.status(401).json({
          status: 'error',
          message: 'Invalid email or password'
        });
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({
          status: 'error',
          message: 'Invalid email or password'
        });
      }

      // Check approval status
      if (user.approvedStatus === 'false' || user.approvedStatus === false) {
        return res.status(403).json({
          status: 'pending',
          message: 'Your account is pending approval. Administrator needs to accept your request. It may take up to 24 hours.'
        });
      }

      // Update last login - try SDK first, fallback to direct API
      try {
        // Try SDK update first
        try {
          await databases.updateDocument(
            process.env.APPWRITE_DATABASE_ID,
            process.env.CONSUMERS_COLLECTION_ID || 'consumers',
            user.$id,
            { lastLogin: String(new Date().toISOString()) }
          );
        } catch (sdkUpdateError) {
          
          // Fallback to direct API
          const databaseId = process.env.APPWRITE_DATABASE_ID;
          const collectionId = process.env.CONSUMERS_COLLECTION_ID || 'consumers';
          const projectId = process.env.APPWRITE_PROJECT_ID;
          const apiKey = process.env.APPWRITE_API_KEY;
          const endpoint = process.env.APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1';

          const updateResponse = await fetch(
            `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents/${user.$id}`,
            {
              method: 'PATCH',
              headers: {
                'Content-Type': 'application/json',
                'X-Appwrite-Project': projectId,
                'X-Appwrite-Key': apiKey
              },
              body: JSON.stringify({
                lastLogin: String(new Date().toISOString())
              })
            }
          );

          if (!updateResponse.ok) {
            const updateErrorData = await updateResponse.text();
          }
        }
      } catch (updateError) {
        // Silent failure for last login update
      }

      // Return success response (don't send password)
      res.status(200).json({
        status: 'success',
        message: 'Login successful',
        data: {
          id: user.$id,
          consumerID: user.consumerID,
          fullname: user.fullname,
          email: user.email,
          accessLevel: user.accessLevel,
          approvedStatus: user.approvedStatus,
          agreeTerms: user.agreeTerms,
          createdAt: user.CreatedAt || user.$createdAt,
          lastLogin: new Date().toISOString()
        }
      });

    } catch (dbError) {
      return res.status(500).json({
        status: 'error',
        message: 'Database connection error'
      });
    }

  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to login',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get All Consumers (for admin management)
app.get('/api/consumers', async (req, res) => {
  try {
    // Basic admin check - in production, use proper JWT validation
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication required. Admin access only.'
      });
    }

    // For now, we'll accept any bearer token as admin validation
    // In production, validate JWT token and check role
    let allConsumers = [];
    
    // Try SDK first, fallback to direct API
    try {
      const consumers = await databases.listDocuments(
        process.env.APPWRITE_DATABASE_ID,
        process.env.CONSUMERS_COLLECTION_ID || 'consumers'
      );
      allConsumers = consumers.documents;
    } catch (sdkError) {
      // Fallback to direct API
      const databaseId = process.env.APPWRITE_DATABASE_ID;
      const collectionId = process.env.CONSUMERS_COLLECTION_ID || 'consumers';
      const projectId = process.env.APPWRITE_PROJECT_ID;
      const apiKey = process.env.APPWRITE_API_KEY;
      const endpoint = process.env.APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1';

      const response = await fetch(
        `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents`,
        {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'X-Appwrite-Project': projectId,
            'X-Appwrite-Key': apiKey
          }
        }
      );

      if (!response.ok) {
        throw new Error(`Direct API error: ${response.status}`);
      }

      const result = await response.json();
      allConsumers = result.documents || [];
    }

    // Format consumers for frontend (remove passwords)
    const formattedConsumers = allConsumers.map(consumer => ({
      id: consumer.$id,
      consumerID: consumer.consumerID,
      name: consumer.fullname,
      email: consumer.email,
      role: consumer.accessLevel,
      status: consumer.approvedStatus === 'true' ? 'active' : 'pending',
      lastActive: consumer.lastLogin || null,
      joinDate: consumer.CreatedAt || consumer.$createdAt,
      agreeTerms: consumer.agreeTerms
    }));

    res.status(200).json({
      status: 'success',
      data: formattedConsumers,
      total: formattedConsumers.length
    });

  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch consumers',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Update Consumer Status/Role (for admin actions)
app.put('/api/consumers/:id', async (req, res) => {
  try {
    // Basic admin check - in production, use proper JWT validation
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication required. Admin access only.'
      });
    }

    // For now, we'll accept any bearer token as admin validation
    // In production, validate JWT token and check role
    const { id } = req.params;
    const { approvedStatus, accessLevel } = req.body;

    // Validate input
    if (!id) {
      return res.status(400).json({
        status: 'error',
        message: 'Consumer ID is required'
      });
    }

    // Prepare update data
    const updateData = {};
    if (approvedStatus !== undefined) {
      updateData.approvedStatus = String(approvedStatus);
    }
    if (accessLevel !== undefined) {
      updateData.accessLevel = String(accessLevel);
    }

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'No valid fields to update'
      });
    }

    let updatedConsumer = null;

    // Try SDK first, fallback to direct API
    try {
      updatedConsumer = await databases.updateDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.CONSUMERS_COLLECTION_ID || 'consumers',
        id,
        updateData
      );
    } catch (sdkError) {
      // Fallback to direct API
      const databaseId = process.env.APPWRITE_DATABASE_ID;
      const collectionId = process.env.CONSUMERS_COLLECTION_ID || 'consumers';
      const projectId = process.env.APPWRITE_PROJECT_ID;
      const apiKey = process.env.APPWRITE_API_KEY;
      const endpoint = process.env.APPWRITE_ENDPOINT;

      const response = await fetch(
        `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents/${id}`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            'X-Appwrite-Project': projectId,
            'X-Appwrite-Key': apiKey
          },
          body: JSON.stringify(updateData)
        }
      );

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Direct API error: ${response.status}`);
      }

      updatedConsumer = await response.json();
    }

    // Format response
    const formattedConsumer = {
      id: updatedConsumer.$id,
      consumerID: updatedConsumer.consumerID,
      name: updatedConsumer.fullname,
      email: updatedConsumer.email,
      role: updatedConsumer.accessLevel,
      status: updatedConsumer.approvedStatus === 'true' ? 'active' : 'pending',
      lastActive: updatedConsumer.lastLogin || null,
      joinDate: updatedConsumer.CreatedAt || updatedConsumer.$createdAt,
      agreeTerms: updatedConsumer.agreeTerms
    };

    res.status(200).json({
      status: 'success',
      message: 'Consumer updated successfully',
      data: formattedConsumer
    });

  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to update consumer',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// ===== MESSAGE ENDPOINTS =====

// Create a new message
app.post('/api/messages', async (req, res) => {
  try {




    
    const { message, userIds, sendToAll = false } = req.body;
    
    if (!message) {
      return res.status(400).json({
        status: 'error',
        message: 'Message field is required'
      });
    }

    if (message.length > 200) {
      return res.status(400).json({
        status: 'error',
        message: 'Message content cannot exceed 200 characters'
      });
    }

    const messageDoc = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.MESSAGES_COLLECTION_ID,
      ID.unique(),
      {
        message: message.trim()
      }
    );



    // Only send notification if sendNotification flag is true
    let notificationResult = null;
    const { sendNotification = false } = req.body;
    
    if (sendNotification) {

      if (sendToAll || !userIds || userIds.length === 0) {

        notificationResult = await notifyAllUsers(
          'New Climate Alert',
          message.trim(),
          {
            messageId: messageDoc.$id,
            type: 'climate_alert'
          }
        );
      } else {

        notificationResult = await notifySpecificUsers(
          userIds,
          'New Climate Alert',
          message.trim(),
          {
            messageId: messageDoc.$id,
            type: 'climate_alert'
          }
        );
      }

    } else {

    }

    res.status(201).json({
      status: 'success',
      message: sendNotification ? 'Message stored and notification sent successfully' : 'Message stored successfully (no notification sent)',
      data: {
        id: messageDoc.$id,
        message: messageDoc.message,
        createdAt: messageDoc.$createdAt,
        targetType: sendToAll ? 'all_users' : 'selected_users',
        targetUsers: sendToAll ? 'all' : userIds,
        notificationSent: sendNotification,
        notification: notificationResult ? {
          sent: notificationResult.success,
          failed: notificationResult.failure,
          errors: notificationResult.errors
        } : null
      }
    });

  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to store message',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? {
        name: error.name,
        code: error.code,
        type: error.type
      } : undefined
    });
  }
});

// Get all messages - direct HTTP approach to avoid SDK request body issue
app.get('/api/messages', async (req, res) => {
  try {

    const url = `${process.env.APPWRITE_ENDPOINT}/databases/${process.env.APPWRITE_DATABASE_ID}/collections/${process.env.MESSAGES_COLLECTION_ID}/documents`;
    

    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'X-Appwrite-Project': process.env.APPWRITE_PROJECT_ID,
        'X-Appwrite-Key': process.env.APPWRITE_API_KEY,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();



    // Process all documents - bring all as requested
    const messages = data.documents.map(doc => ({
      $id: doc.$id,
      message: doc.message,
      createdAt: doc.$createdAt
    }));

    // Sort by newest first (no limit - bring all)
    messages.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));



    res.json({
      status: 'success',
      data: messages,
      total: data.total
    });

  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to retrieve messages',
      error: error.message
    });
  }
});

// ===== FCM TOKEN ENDPOINTS =====

// Save or update FCM token
app.post('/api/tokens', async (req, res) => {
  try {
    // Check if tokens collection is configured
    if (!process.env.TOKENS_COLLECTION_ID || process.env.TOKENS_COLLECTION_ID === 'tokens') {
      return res.json({
        status: 'success',
        message: 'Tokens collection not configured - token saved locally (mock)',
        data: {
          id: 'mock-id',
          token: req.body.token,
          isActive: true
        }
      });
    }

    const { fcmToken, userId } = req.body;
    
    if (!fcmToken) {
      return res.status(400).json({
        status: 'error',
        message: 'fcmToken is required'
      });
    }

    if (!userId) {
      return res.status(400).json({
        status: 'error',
        message: 'userId is required'
      });
    }

    // Check if token already exists
    try {
      const existingTokens = await databases.listDocuments(
        process.env.APPWRITE_DATABASE_ID,
        process.env.TOKENS_COLLECTION_ID,
        [Query.equal('fcmToken', fcmToken)]
      );

      if (existingTokens.documents.length > 0) {
        const existingToken = existingTokens.documents[0];
        const updatedToken = await databases.updateDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.TOKENS_COLLECTION_ID,
          existingToken.$id,
          {
            userId: userId,
            isActive: true
          }
        );

        return res.json({
          status: 'success',
          message: 'FCM token updated successfully',
          data: {
            id: updatedToken.$id,
            fcmToken: updatedToken.fcmToken,
            userId: updatedToken.userId,
            isActive: updatedToken.isActive
          }
        });
      }
    } catch (queryError) {

    }

    // Create new token
    const newToken = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.TOKENS_COLLECTION_ID,
      ID.unique(),
      {
        fcmToken: fcmToken,
        userId: userId,
        isActive: true
      }
    );



    res.status(201).json({
      status: 'success',
      message: 'FCM token saved successfully',
      data: {
        id: newToken.$id,
        fcmToken: newToken.fcmToken,
        userId: newToken.userId,
        isActive: newToken.isActive
      }
    });

  } catch (error) {

    res.status(500).json({
      status: 'error',
      message: 'Failed to save FCM token',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get all FCM tokens - direct HTTP approach similar to messages
app.get('/api/tokens', async (req, res) => {
  try {
    // Check if tokens collection is configured
    if (!process.env.TOKENS_COLLECTION_ID || process.env.TOKENS_COLLECTION_ID === 'tokens') {
      return res.json({
        status: 'success',
        message: 'Tokens collection not configured yet',
        data: {
          tokens: [],
          count: 0,
          total: 0
        }
      });
    }

    const { active = 'true' } = req.query;

    const queries = [
      Query.orderDesc('$createdAt'),
      Query.limit(1000)
    ];

    if (active === 'true') {
      queries.push(Query.equal('isActive', true));
    }


    const url = `${process.env.APPWRITE_ENDPOINT}/databases/${process.env.APPWRITE_DATABASE_ID}/collections/${process.env.TOKENS_COLLECTION_ID}/documents`;
    

    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'X-Appwrite-Project': process.env.APPWRITE_PROJECT_ID,
        'X-Appwrite-Key': process.env.APPWRITE_API_KEY,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();



    // Process all token documents
    const tokens = data.documents.map(doc => ({
      $id: doc.$id,
      fcmToken: doc.fcmToken,
      userId: doc.userId || null,
      isActive: doc.isActive !== undefined ? doc.isActive : true,
      createdAt: doc.$createdAt,
      updatedAt: doc.$updatedAt || doc.$createdAt
    }));

    // Sort by newest first (no limit - bring all)
    tokens.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));



    res.json({
      status: 'success',
      message: `Retrieved ${tokens.length} FCM tokens`,
      data: {
        tokens: tokens,
        count: tokens.length,
        total: data.total,
        activeCount: tokens.filter(t => t.isActive).length
      }
    });

  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to retrieve FCM tokens',
      error: error.message,
      debug: {
        database: process.env.APPWRITE_DATABASE_ID,
        collection: process.env.TOKENS_COLLECTION_ID
      }
    });
  }
});

// ===== RENDER API ENDPOINTS (ADMIN ONLY) =====

// Get all Render services
app.get('/api/admin/render/services', async (req, res) => {
  try {
    // Verify admin access
    await verifyAdminAccess(req.headers.authorization);

    const limit = req.query.limit || 20;
    const renderData = await makeRenderAPIRequest('GET', `/services?limit=${limit}`);
    
    // Extract services from the Render API response format
    const services = renderData.map(item => ({
      id: item.service.id,
      name: item.service.name,
      type: item.service.type,
      status: item.service.suspended === 'not_suspended' ? 'running' : 'suspended',
      url: item.service.serviceDetails?.url || null,
      env: item.service.serviceDetails?.env || 'unknown',
      updatedAt: item.service.updatedAt,
      dashboardUrl: item.service.dashboardUrl
    }));

    res.json({
      status: 'success',
      message: `Retrieved ${services.length} services`,
      services: services
    });

  } catch (error) {
    console.error('Get services error:', error.message || 'Request failed');
    res.status(error.message?.includes('Authentication') ? 401 : 500).json({
      status: 'error',
      message: process.env.NODE_ENV === 'production' ? 'Failed to retrieve services' : error.message
    });
  }
});

// Get specific service details
app.get('/api/admin/render/services/:serviceId', async (req, res) => {
  try {
    // Verify admin access
    await verifyAdminAccess(req.headers.authorization);

    const { serviceId } = req.params;
    const service = await makeRenderAPIRequest('GET', `/services/${serviceId}`);

    res.json({
      status: 'success',
      message: 'Service details retrieved successfully',
      data: service
    });

  } catch (error) {
    console.error('Get service error:', error.message || 'Operation failed');
    res.status(error.message.includes('Authentication') ? 401 : 500).json({
      status: 'error',
      message: error.message || 'Failed to retrieve service details'
    });
  }
});

// Deploy a service
app.post('/api/admin/render/services/:serviceId/deploy', async (req, res) => {
  try {
    // Verify admin access
    await verifyAdminAccess(req.headers.authorization);

    const { serviceId } = req.params;
    const deployment = await makeRenderAPIRequest('POST', `/services/${serviceId}/deploys`);

    res.json({
      status: 'success',
      message: 'Service deployment initiated successfully',
      data: deployment
    });

  } catch (error) {
    console.error('Deploy service error:', error.message || 'Operation failed');
    res.status(error.message.includes('Authentication') ? 401 : 500).json({
      status: 'error',
      message: error.message || 'Failed to deploy service'
    });
  }
});

// Suspend a service
app.post('/api/admin/render/services/:serviceId/suspend', async (req, res) => {
  try {
    // Verify admin access
    await verifyAdminAccess(req.headers.authorization);

    const { serviceId } = req.params;
    const result = await makeRenderAPIRequest('POST', `/services/${serviceId}/suspend`);

    res.json({
      status: 'success',
      message: 'Service suspended successfully',
      data: result
    });

  } catch (error) {
    console.error('Suspend service error:', error.message || 'Operation failed');
    res.status(error.message.includes('Authentication') ? 401 : 500).json({
      status: 'error',
      message: error.message || 'Failed to suspend service'
    });
  }
});

// Resume a service
app.post('/api/admin/render/services/:serviceId/resume', async (req, res) => {
  try {
    // Verify admin access
    await verifyAdminAccess(req.headers.authorization);

    const { serviceId } = req.params;
    const result = await makeRenderAPIRequest('POST', `/services/${serviceId}/resume`);

    res.json({
      status: 'success',
      message: 'Service resumed successfully',
      data: result
    });

  } catch (error) {
    console.error('Resume service error:', error.message || 'Operation failed');
    res.status(error.message.includes('Authentication') ? 401 : 500).json({
      status: 'error',
      message: error.message || 'Failed to resume service'
    });
  }
});

// Restart a service
app.post('/api/admin/render/services/:serviceId/restart', async (req, res) => {
  try {
    // Verify admin access
    await verifyAdminAccess(req.headers.authorization);

    const { serviceId } = req.params;
    const result = await makeRenderAPIRequest('POST', `/services/${serviceId}/restart`);

    res.json({
      status: 'success',
      message: 'Service restarted successfully',
      data: result
    });

  } catch (error) {
    console.error('Restart service error:', error.message || 'Operation failed');
    res.status(error.message.includes('Authentication') ? 401 : 500).json({
      status: 'error',
      message: error.message || 'Failed to restart service'
    });
  }
});

// Get service deployments
app.get('/api/admin/render/services/:serviceId/deployments', async (req, res) => {
  try {
    // Verify admin access
    await verifyAdminAccess(req.headers.authorization);

    const { serviceId } = req.params;
    const limit = req.query.limit || 10;
    const deployments = await makeRenderAPIRequest('GET', `/services/${serviceId}/deploys?limit=${limit}`);

    res.json({
      status: 'success',
      message: 'Service deployments retrieved successfully',
      data: deployments
    });

  } catch (error) {
    console.error('Get deployments error:', error.message || 'Operation failed');
    res.status(error.message.includes('Authentication') ? 401 : 500).json({
      status: 'error',
      message: error.message || 'Failed to retrieve service deployments'
    });
  }
});

// ===== CLIMATE REPORTS API ENDPOINTS =====

// Save climate report to database (Admin only)
app.post('/api/climate-reports', fileUploadLimiter, validateFileUpload, async (req, res) => {
  try {
    const { reportData, consumerId, fileData } = req.body;

    if (!reportData || !consumerId) {
      return res.status(400).json({
        status: 'error',
        message: 'reportData and consumerId are required'
      });
    }

    // Verify admin access by checking Consumers collection directly
    try {
      const user = await findUserByConsumerID(consumerId);

      if (!user) {
        return res.status(404).json({
          status: 'error',
          message: 'User not found'
        });
      }

      if (user.accessLevel !== 'admin') {
        return res.status(403).json({
          status: 'error',
          message: 'Access denied. Only admin users can generate climate reports.'
        });
      }

    } catch (adminError) {
      return res.status(500).json({
        status: 'error',
        message: 'Error verifying admin access: ' + adminError.message
      });
    }

    // Handle file upload to Appwrite Storage
    let fileUrl = '';
    let fileSize = '0 KB';

    if (fileData) {
      try {
        // If fileData is base64, convert to buffer
        let fileBuffer;
        let filename = `climate_report_${Date.now()}.pdf`;

        if (fileData.startsWith('data:')) {
          // Handle base64 data URL
          const base64Data = fileData.split(',')[1];
          fileBuffer = Buffer.from(base64Data, 'base64');
          // Extract filename from data URL if available
          const mimeMatch = fileData.match(/data:([^;]+)/);
          if (mimeMatch && mimeMatch[1] === 'application/pdf') {
            filename = `climate_report_${Date.now()}.pdf`;
          }
        } else {
          // Assume it's already a buffer or handle as needed
          fileBuffer = Buffer.from(fileData, 'base64');
        }

        // Upload to Appwrite Storage using buffer directly
        const uploadResult = await uploadFileToAppwriteStorage(fileBuffer, filename);
        fileUrl = uploadResult.fileUrl;

        // Calculate file size from buffer
        const sizeInMB = (fileBuffer.length / (1024 * 1024)).toFixed(2);
        fileSize = `${sizeInMB} MB`;

      } catch (uploadError) {
        console.error('❌ File upload failed:', uploadError.message || 'Upload failed');
        return res.status(500).json({
          status: 'error',
          message: 'Failed to upload file to storage',
          error: uploadError.message
        });
      }
    } else {
      // Use provided fileUrl if no file data
      fileUrl = reportData.fileUrl || '';
      fileSize = reportData.fileSize || '0 KB';
    }

    // Generate unique ReportId
    const reportId = `RPT_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Create simplified climate report document
    const reportDocument = {
      reportId: String(reportId),
      consumerId: String(consumerId),
      title: String(reportData.title || ''),
      type: String(reportData.type || ''),
      period: String(reportData.period || ''),
      region: String(reportData.region || ''),
      generatedDate: String(reportData.generatedDate || new Date().toISOString()),
      fileSize: String(fileSize),
      status: String(reportData.status || 'completed'),
      downloadCount: parseInt(reportData.downloadCount) || 0, // Integer for Appwrite
      fileUrl: String(fileUrl),
      isPublic: Boolean(reportData.isPublic || false)
    };

    const collectionId = process.env.CLIMATE_REPORTS_COLLECTION_ID || 'climate_reports';
    
    const savedReport = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      collectionId,
      ID.unique(),
      reportDocument
    );

    res.status(201).json({
      status: 'success',
      message: 'Climate report saved successfully',
      data: {
        id: savedReport.$id,
        reportId: savedReport.reportId,
        title: savedReport.title,
        fileUrl: savedReport.fileUrl,
        createdAt: savedReport.$createdAt,
        consumerId: savedReport.consumerId
      }
    });

  } catch (error) {
    console.error('❌ Save climate report error:', {
      message: error.message,
      type: error.type,
      code: error.code,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
    
    // Check if it's a collection not found error
    if (error.code === 404 || error.type === 'collection_not_found') {
      return res.status(404).json({
        status: 'error',
        message: 'Climate reports collection does not exist in Appwrite',
        error: 'Please create the climate_reports collection in Appwrite console',
        code: error.code,
        type: error.type,
        solution: {
          step1: 'Go to Appwrite Console → Database → Collections',
          step2: 'Create new collection with ID: climate_reports',
          step3: 'Add attributes as per APPWRITE_DATABASE_SCHEMA.md',
          step4: 'Set proper permissions for read/write access'
        }
      });
    }
    
    res.status(500).json({
      status: 'error',
      message: 'Failed to save climate report',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? {
        type: error.type,
        code: error.code,
        message: error.message
      } : undefined
    });
  }
});

// Get user by consumerID for access verification
app.get('/api/user/:consumerID', async (req, res) => {
  try {
    const { consumerID } = req.params;
    
    if (!consumerID) {
      return res.status(400).json({ error: 'Consumer ID is required' });
    }
    
    const user = await findUserByConsumerID(consumerID);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      consumerID: user.consumerID,
      accessLevel: user.accessLevel,
      fullname: user.fullname
    });
    
  } catch (error) {
    console.error('❌ Error looking up user:', error.message || 'Lookup failed');
    res.status(500).json({ 
      status: 'error',
      message: 'Failed to retrieve user information'
    });
  }
});

// Get all climate reports (simplified, no sync)
app.get('/api/climate-reports', async (req, res) => {
  try {
    const { limit = 50 } = req.query;

    // Use direct API call to avoid SDK Query issues
    const databaseId = process.env.APPWRITE_DATABASE_ID;
    const collectionId = process.env.CLIMATE_REPORTS_COLLECTION_ID || 'climate_reports';
    const projectId = process.env.APPWRITE_PROJECT_ID;
    const apiKey = process.env.APPWRITE_API_KEY;
    const endpoint = process.env.APPWRITE_ENDPOINT;

    const fullUrl = `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents?limit=${limit}&orderType=desc&orderAttributes=$createdAt`;

    const apiResponse = await fetch(fullUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Appwrite-Project': projectId,
        'X-Appwrite-Key': apiKey
      }
    });

    if (!apiResponse.ok) {
      throw new Error(`HTTP ${apiResponse.status}: ${apiResponse.statusText}`);
    }

    const response = await apiResponse.json();

    const reports = response.documents.map(report => ({
      id: report.$id,
      reportId: report.reportId,
      title: report.title || 'Untitled Report',
      type: report.type || 'comprehensive',
      period: report.period || 'monthly',
      region: report.region || 'global',
      consumerId: report.consumerId || '',
      status: report.status || 'completed',
      downloadCount: parseInt(report.downloadCount) || 0, // Return as integer for frontend
      fileSize: report.fileSize || '0 KB',
      fileUrl: report.fileUrl || '',
      generatedDate: report.generatedDate || report.$createdAt,
      isPublic: report.isPublic || false
    }));

    res.json({
      status: 'success',
      data: {
        reports: reports,
        total: response.total || 0,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Get climate reports error:', error.message || 'Operation failed');
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch climate reports',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get climate reports for a specific consumer
app.get('/api/climate-reports/consumer/:consumerId', async (req, res) => {
  try {
    const { consumerId } = req.params;
    const { limit = 50 } = req.query;

    if (!consumerId) {
      return res.status(400).json({
        status: 'error',
        message: 'consumerId is required'
      });
    }

    // Use direct API call to avoid SDK Query issues
    const databaseId = process.env.APPWRITE_DATABASE_ID;
    const collectionId = process.env.CLIMATE_REPORTS_COLLECTION_ID || 'climate_reports';
    const projectId = process.env.APPWRITE_PROJECT_ID;
    const apiKey = process.env.APPWRITE_API_KEY;
    const endpoint = process.env.APPWRITE_ENDPOINT;

    const fullUrl = `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents?limit=${limit}&orderType=desc&orderAttributes=$createdAt`;

    const apiResponse = await fetch(fullUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Appwrite-Project': projectId,
        'X-Appwrite-Key': apiKey
      }
    });

    if (!apiResponse.ok) {
      throw new Error(`HTTP ${apiResponse.status}: ${apiResponse.statusText}`);
    }

    const reports = await apiResponse.json();
    
    // Filter by consumerId manually since we can't use Query.equal
    const filteredReports = reports.documents ? 
      reports.documents.filter(doc => doc.consumerId === consumerId) : [];

    res.json({
      status: 'success',
      data: {
        reports: filteredReports,
        total: filteredReports.length
      }
    });

  } catch (error) {
    console.error('Get climate reports error:', error.message || 'Operation failed');
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch climate reports',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Update climate report (Admin only)
app.put('/api/climate-reports/:reportId', async (req, res) => {
  try {
    const { reportId } = req.params;
    const { updateData, consumerId } = req.body;

    if (!reportId || !updateData || !consumerId) {
      return res.status(400).json({
        status: 'error',
        message: 'reportId, updateData, and consumerId are required'
      });
    }

    // Verify admin access by checking user directly (not using Bearer token)
    try {
      const user = await findUserByConsumerID(consumerId);

      if (!user) {
        return res.status(404).json({
          status: 'error',
          message: `User with consumerID '${consumerId}' not found in database. Please ensure you are logged in and your account exists.`
        });
      }

      if (user.accessLevel !== 'admin') {
        return res.status(403).json({
          status: 'error',
          message: `Access denied. Current access level: '${user.accessLevel}', required: 'admin'. Contact administrator to update your access level.`
        });
      }

      if (user.approvedStatus !== 'true' && user.approvedStatus !== true) {
        return res.status(403).json({
          status: 'error',
          message: 'Account not approved. Contact administrator.'
        });
      }

    } catch (adminError) {
      return res.status(500).json({
        status: 'error',
        message: 'Error verifying admin access: ' + adminError.message
      });
    }

    // Use direct API call to get document and verify ownership
    const databaseId = process.env.APPWRITE_DATABASE_ID;
    const collectionId = process.env.CLIMATE_REPORTS_COLLECTION_ID || 'climate_reports';
    const projectId = process.env.APPWRITE_PROJECT_ID;
    const apiKey = process.env.APPWRITE_API_KEY;
    const endpoint = process.env.APPWRITE_ENDPOINT;

    // Get the document first to verify ownership
    const getUrl = `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents/${reportId}`;

    const getResponse = await fetch(getUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Appwrite-Project': projectId,
        'X-Appwrite-Key': apiKey
      }
    });

    if (!getResponse.ok) {
      if (getResponse.status === 404) {
        return res.status(404).json({
          status: 'error',
          message: 'Report not found'
        });
      }
      throw new Error(`HTTP ${getResponse.status}: ${getResponse.statusText}`);
    }

    const existingReport = await getResponse.json();

    if (existingReport.consumerId !== consumerId) {
      return res.status(403).json({
        status: 'error',
        message: 'Access denied to update this report'
      });
    }

    // Handle download count increment specifically
    const finalUpdateData = { ...updateData };

    if (updateData.downloadCount !== undefined) {
      // If downloadCount is provided as a number to increment by
      const incrementBy = parseInt(updateData.downloadCount) || 1;
      const currentCount = parseInt(existingReport.downloadCount) || 0;
      finalUpdateData.downloadCount = currentCount + incrementBy; // Keep as integer for Appwrite
    }

    // Ensure we have data to update
    if (Object.keys(finalUpdateData).length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'No valid data to update'
      });
    }

    // Convert other fields to proper types
    if (finalUpdateData.fileUrl !== undefined) {
      finalUpdateData.fileUrl = String(finalUpdateData.fileUrl);
    }
    if (finalUpdateData.title !== undefined) {
      finalUpdateData.title = String(finalUpdateData.title);
    }

    // Update the document using SDK (more reliable than direct API)
    const updatedReport = await databases.updateDocument(
      databaseId,
      collectionId,
      reportId,
      finalUpdateData
    );

    res.json({
      status: 'success',
      message: 'Climate report updated successfully',
      data: updatedReport
    });

  } catch (error) {
    console.error('Update climate report error:', error.message || 'Operation failed');
    res.status(500).json({
      status: 'error',
      message: 'Failed to update climate report',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Delete climate report (Admin only)
app.delete('/api/climate-reports/:reportId', async (req, res) => {
  try {
    const { reportId } = req.params;
    const { consumerId } = req.body;

    if (!reportId || !consumerId) {
      return res.status(400).json({
        status: 'error',
        message: 'reportId and consumerId are required'
      });
    }

    // Verify admin access by checking user directly (not using Bearer token)
    try {
      const user = await findUserByConsumerID(consumerId);

      if (!user) {
        return res.status(404).json({
          status: 'error',
          message: `User with consumerID '${consumerId}' not found in database. Please ensure you are logged in and your account exists.`
        });
      }

      if (user.accessLevel !== 'admin') {
        return res.status(403).json({
          status: 'error',
          message: `Access denied. Current access level: '${user.accessLevel}', required: 'admin'. Contact administrator to update your access level.`
        });
      }

      if (user.approvedStatus !== 'true' && user.approvedStatus !== true) {
        return res.status(403).json({
          status: 'error',
          message: 'Account not approved. Contact administrator.'
        });
      }

    } catch (adminError) {
      return res.status(500).json({
        status: 'error',
        message: 'Error verifying admin access: ' + adminError.message
      });
    }

    // Use direct API call to get document and verify ownership
    const databaseId = process.env.APPWRITE_DATABASE_ID;
    const collectionId = process.env.CLIMATE_REPORTS_COLLECTION_ID || 'climate_reports';
    const projectId = process.env.APPWRITE_PROJECT_ID;
    const apiKey = process.env.APPWRITE_API_KEY;
    const endpoint = process.env.APPWRITE_ENDPOINT;

    // Get the document first to verify ownership
    const getUrl = `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents/${reportId}`;

    const getResponse = await fetch(getUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Appwrite-Project': projectId,
        'X-Appwrite-Key': apiKey
      }
    });

    if (!getResponse.ok) {
      if (getResponse.status === 404) {
        return res.status(404).json({
          status: 'error',
          message: 'Report not found'
        });
      }
      throw new Error(`HTTP ${getResponse.status}: ${getResponse.statusText}`);
    }

    const existingReport = await getResponse.json();

    if (existingReport.consumerId !== consumerId) {
      return res.status(403).json({
        status: 'error',
        message: 'Access denied to delete this report'
      });
    }

    // Delete the document
    const deleteUrl = `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents/${reportId}`;

    const deleteResponse = await fetch(deleteUrl, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-Appwrite-Project': projectId,
        'X-Appwrite-Key': apiKey
      }
    });

    if (!deleteResponse.ok) {
      throw new Error(`HTTP ${deleteResponse.status}: ${deleteResponse.statusText}`);
    }

    res.json({
      status: 'success',
      message: 'Climate report deleted successfully'
    });

  } catch (error) {
    console.error('Delete climate report error:', error.message || 'Operation failed');
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete climate report',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get climate report statistics
app.get('/api/climate-reports/:consumerId/statistics', async (req, res) => {
  try {
    const { consumerId } = req.params;

    if (!consumerId) {
      return res.status(400).json({
        status: 'error',
        message: 'consumerId is required'
      });
    }

    // Use direct API call to avoid SDK Query issues
    const databaseId = process.env.APPWRITE_DATABASE_ID;
    const collectionId = process.env.CLIMATE_REPORTS_COLLECTION_ID || 'climate_reports';
    const projectId = process.env.APPWRITE_PROJECT_ID;
    const apiKey = process.env.APPWRITE_API_KEY;
    const endpoint = process.env.APPWRITE_ENDPOINT;

    const fullUrl = `${endpoint}/databases/${databaseId}/collections/${collectionId}/documents?limit=1000`;

    const apiResponse = await fetch(fullUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Appwrite-Project': projectId,
        'X-Appwrite-Key': apiKey
      }
    });

    if (!apiResponse.ok) {
      throw new Error(`HTTP ${apiResponse.status}: ${apiResponse.statusText}`);
    }

    const reports = await apiResponse.json();
    
    // Filter by consumerId manually
    const reportsData = reports.documents ? 
      reports.documents.filter(doc => doc.consumerId === consumerId) : [];
    const statistics = {
      totalReports: reportsData.length,
      totalDownloads: reportsData.reduce((sum, report) => sum + (parseInt(report.downloadCount) || 0), 0),
      reportsByType: {},
      reportsByRegion: {},
      recentActivity: reportsData.slice(0, 10),
      totalStorageUsed: reportsData.reduce((total, report) => {
        const sizeStr = report.fileSize || '0 MB';
        const sizeValue = parseFloat(sizeStr.replace(' MB', ''));
        return total + (isNaN(sizeValue) ? 0 : sizeValue);
      }, 0)
    };

    // Group by type and region
    reportsData.forEach(report => {
      statistics.reportsByType[report.type] = (statistics.reportsByType[report.type] || 0) + 1;
      statistics.reportsByRegion[report.region] = (statistics.reportsByRegion[report.region] || 0) + 1;
    });

    res.json({
      status: 'success',
      data: statistics
    });

  } catch (error) {
    console.error('Get climate report statistics error:', error.message || 'Operation failed');
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch statistics',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


// ===== REPORTS API ROUTES (MongoDB) =====

// Include the reports API routes
const reportsRoutes = require('./api/reports');
app.use('/api/reports', reportsRoutes);

// ===== NOTIFICATION ENDPOINTS =====

// Send notification to specific users
app.post('/api/notifications/send-to-users', async (req, res) => {
  try {
    const { title, body, userIds, data = {} } = req.body;
    
    if (!title || !body) {
      return res.status(400).json({
        status: 'error',
        message: 'Title and body are required for notifications'
      });
    }

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'userIds array is required for user-specific notifications'
      });
    }



    
    const result = await notifySpecificUsers(userIds, title, body, {
      ...data,
      type: 'user_specific'
    });
    
    res.json({
      status: 'success',
      message: `Notification sent to specific users`,
      data: {
        targetUsers: userIds,
        successCount: result.success,
        failureCount: result.failure,
        title: title,
        body: body,
        timestamp: new Date().toISOString(),
        errors: result.errors.length > 0 ? result.errors : undefined
      }
    });



  } catch (error) {

    res.status(500).json({
      status: 'error',
      message: 'Failed to send user-specific notification',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Broadcast notification to all users
app.post('/api/notifications/broadcast', async (req, res) => {
  try {
    const { title, body, data = {} } = req.body;
    
    if (!title || !body) {
      return res.status(400).json({
        status: 'error',
        message: 'Title and body are required for notifications'
      });
    }


    
    // Get all active tokens and send FCM notification
    const tokens = await getActiveTokens();
    
    if (tokens.length === 0) {
      return res.json({
        status: 'success',
        message: 'No active devices to send notifications to',
        data: {
          totalTargets: 0,
          successCount: 0,
          failureCount: 0,
          title: title,
          body: body,
          timestamp: new Date().toISOString()
        }
      });
    }

    const result = await sendFCMNotification(title, body, tokens, {
      ...data,
      type: 'broadcast'
    });
    
    res.json({
      status: 'success',
      message: `Notification broadcast completed`,
      data: {
        totalTargets: tokens.length,
        successCount: result.success,
        failureCount: result.failure,
        title: title,
        body: body,
        timestamp: new Date().toISOString(),
        errors: result.errors.length > 0 ? result.errors : undefined
      }
    });



  } catch (error) {

    res.status(500).json({
      status: 'error',
      message: 'Failed to broadcast notification',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// ===== ERROR HANDLING =====

app.use('*', (req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found'
  });
});

// Global error handler with sanitized error messages
app.use((error, req, res, next) => {
  // Log error for debugging (server-side only)
  console.error('Error:', {
    message: error.message,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });
  
  // Send sanitized error to client
  res.status(error.status || 500).json({
    status: 'error',
    message: sanitizeErrorMessage(error),
    ...(process.env.NODE_ENV === 'development' && { 
      details: error.message,
      stack: error.stack 
    })
  });
});

// Start server
app.listen(PORT, () => {
});

// Graceful shutdown
process.on('SIGINT', () => {

  process.exit(0);
});

module.exports = app;
