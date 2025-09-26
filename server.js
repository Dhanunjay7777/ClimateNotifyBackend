const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Client, Databases, ID, Query } = require('node-appwrite');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

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

/**
 * Send notification to specific users by userIds
 */
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
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX_REQUESTS || 100,
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again later.'
  }
});
app.use('/api/', limiter);

// Test endpoint for debugging
app.get('/api/test', (req, res) => {
  res.json({
    status: 'success',
    message: 'API is working',
    environment: {
      NODE_ENV: process.env.NODE_ENV,
      DATABASE_ID: process.env.APPWRITE_DATABASE_ID,
      MESSAGES_COLLECTION_ID: process.env.MESSAGES_COLLECTION_ID,
      TOKENS_COLLECTION_ID: process.env.TOKENS_COLLECTION_ID
    },
    timestamp: new Date().toISOString()
  });
});

// Minimal database test
app.get('/api/test-db', async (req, res) => {
  try {

    
    // Test the most basic database operation - just getting database info
    const dbList = await databases.list();

    
    res.json({
      status: 'success',
      message: 'Database connection successful',
      databaseCount: dbList.total
    });
  } catch (error) {

    res.status(500).json({
      status: 'error',
      message: 'Database connection failed',
      error: error.message
    });
  }
});

// Simple collection test endpoint
app.get('/api/test-collection', async (req, res) => {
  try {



    
    // First try to list all collections to see what's available

    try {
      const collections = await databases.list();

    } catch (listError) {

    }
    
    // Try the simplest possible query
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.MESSAGES_COLLECTION_ID,
      []
    );
    

    
    res.json({
      status: 'success',
      message: 'Collection access successful',
      totalDocuments: response.total,
      documentsReturned: response.documents.length,
      firstDocument: response.documents[0] ? {
        $id: response.documents[0].$id,
        message: response.documents[0].message,
        $createdAt: response.documents[0].$createdAt
      } : null
    });
  } catch (error) {

    res.status(500).json({
      status: 'error',
      message: 'Collection access failed',
      error: error.message,
      code: error.code,
      type: error.type,
      debug: {
        database: process.env.APPWRITE_DATABASE_ID,
        collection: process.env.MESSAGES_COLLECTION_ID
      }
    });
  }
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    await databases.list();
    res.json({
      status: 'success',
      message: 'Server is running and connected to Appwrite',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      appwrite: {
        endpoint: process.env.APPWRITE_ENDPOINT,
        project: process.env.APPWRITE_PROJECT_ID,
        database: process.env.APPWRITE_DATABASE_ID
      }
    });
  } catch (error) {

    res.status(500).json({ 
      status: 'error', 
      message: 'Server is running but Appwrite connection failed', 
      error: error.message 
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

// Test endpoint for checking email/consumerID uniqueness (development only)
if (process.env.NODE_ENV === 'development') {
  app.get('/api/test/check-unique/:type/:value', async (req, res) => {
    try {
      const { type, value } = req.params;
      
      if (type === 'email') {
        const exists = await checkEmailExists(value);
        res.json({
          status: 'success',
          type: 'email',
          value: value,
          exists: exists,
          message: exists ? 'Email already exists' : 'Email is unique'
        });
      } else if (type === 'consumerid') {
        const exists = await checkConsumerIdExists(value);
        res.json({
          status: 'success',
          type: 'consumerID',
          value: value,
          exists: exists,
          message: exists ? 'ConsumerID already exists' : 'ConsumerID is unique'
        });
      } else {
        res.status(400).json({
          status: 'error',
          message: 'Invalid type. Use "email" or "consumerid"'
        });
      }
    } catch (error) {
      res.status(500).json({
        status: 'error',
        message: 'Failed to check uniqueness',
        error: error.message
      });
    }
  });
}

// Global error handler
app.use((error, req, res, next) => {

  
  res.status(error.status || 500).json({
    status: 'error',
    message: error.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
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
