const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const router = express.Router();

// MongoDB Configuration
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB_NAME || 'Climate';
const COLLECTION_NAME = process.env.MONGODB_COLLECTION_NAME || 'reports';

// AWS S3 Configuration (v3)
const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

let db = null;

// Initialize MongoDB connection
async function initDB() {
  try {
    if (!db) {
      const client = new MongoClient(MONGODB_URI);
      await client.connect();
      db = client.db(DB_NAME);
    }
    return db;
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    throw error;
  }
}

// Get all reports with pagination and filtering
router.get('/', async (req, res) => {
  try {
    const database = await initDB();
    const collection = database.collection(COLLECTION_NAME);
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 15;
    const skip = (page - 1) * limit;
    
    // Build filter query
    const filter = {};
    
    // Only apply filters if specifically requested
    if (req.query.userId && req.query.userId !== 'all') {
      filter.userid = req.query.userId;
    }
    if (req.query.search && req.query.search.trim()) {
      filter.$or = [
        { description: { $regex: req.query.search, $options: 'i' } },
        { userid: { $regex: req.query.search, $options: 'i' } }
      ];
    }
    if (req.query.filter === 'recent') {
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      filter.raisedat = { $gte: sevenDaysAgo };
    }
    if (req.query.filter === 'thisMonth') {
      const now = new Date();
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      filter.raisedat = {
        $gte: startOfMonth,
        $lte: endOfMonth
      };
    }
    
    // Get reports with pagination
    const reports = await collection
      .find(filter, {
        projection: {
          userid: 1,
          description: 1,
          imageurl: 1,
          s3Key: 1,
          raisedat: 1,
          location: 1,
          filename: 1,
          filesize: 1,
          mimetype: 1
        }
      })
      .sort({ raisedat: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    // Transform reports to match frontend expectations
    const transformedReports = reports.map(report => ({
      ...report,
      imageurl: report.s3Key || report.imageurl, // Use s3Key if available, fallback to imageurl
      location: report.location || 'Unknown Location'
    }));
    
    // Get total count for pagination
    const totalReports = await collection.countDocuments(filter);
    
    // Get monthly statistics
    const currentMonth = new Date().getMonth() + 1;
    const currentYear = new Date().getFullYear();
    const monthStartDate = new Date(currentYear, currentMonth - 1, 1);
    const monthEndDate = new Date(currentYear, currentMonth, 0);
    
    const monthlyStats = await collection.aggregate([
      {
        $match: {
          raisedat: {
            $gte: monthStartDate,
            $lte: monthEndDate
          }
        }
      },
      {
        $group: {
          _id: null,
          totalReports: { $sum: 1 },
          totalFileSize: { $sum: '$filesize' },
          avgFileSize: { $avg: '$filesize' },
          reportsByType: {
            $push: {
              description: '$description',
              count: 1
            }
          }
        }
      }
    ]).toArray();
    
    // Get daily reports for this month
    const dailyReports = await collection.aggregate([
      {
        $match: {
          raisedat: {
            $gte: monthStartDate,
            $lte: monthEndDate
          }
        }
      },
      {
        $group: {
          _id: {
            day: { $dayOfMonth: '$raisedat' },
            month: { $month: '$raisedat' },
            year: { $year: '$raisedat' }
          },
          count: { $sum: 1 },
          totalSize: { $sum: '$filesize' }
        }
      },
      {
        $sort: { '_id.day': 1 }
      }
    ]).toArray();
    
    res.json({
      status: 'success',
      data: {
        reports: transformedReports,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalReports / limit),
          totalReports: totalReports,
          hasNext: page < Math.ceil(totalReports / limit),
          hasPrev: page > 1
        },
        statistics: {
          monthly: monthlyStats[0] || {
            totalReports: 0,
            totalFileSize: 0,
            avgFileSize: 0,
            reportsByType: []
          },
          daily: dailyReports
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch reports',
      error: error.message
    });
  }
});

// Get report statistics for dashboard
router.get('/stats', async (req, res) => {
  try {
    const database = await initDB();
    const collection = database.collection(COLLECTION_NAME);
    
    const now = new Date();
    const currentMonth = now.getMonth() + 1;
    const currentYear = now.getFullYear();
    const lastMonth = currentMonth === 1 ? 12 : currentMonth - 1;
    const lastMonthYear = currentMonth === 1 ? currentYear - 1 : currentYear;
    
    // Current month range
    const currentMonthStart = new Date(currentYear, currentMonth - 1, 1);
    const currentMonthEnd = new Date(currentYear, currentMonth, 0);
    
    // Last month range
    const lastMonthStart = new Date(lastMonthYear, lastMonth - 1, 1);
    const lastMonthEnd = new Date(lastMonthYear, lastMonth, 0);
    
    // Get current month stats
    const currentMonthStats = await collection.aggregate([
      {
        $match: {
          raisedat: {
            $gte: currentMonthStart,
            $lte: currentMonthEnd
          }
        }
      },
      {
        $group: {
          _id: null,
          totalReports: { $sum: 1 },
          totalFileSize: { $sum: '$filesize' },
          avgFileSize: { $avg: '$filesize' }
        }
      }
    ]).toArray();
    
    // Get last month stats
    const lastMonthStats = await collection.aggregate([
      {
        $match: {
          raisedat: {
            $gte: lastMonthStart,
            $lte: lastMonthEnd
          }
        }
      },
      {
        $group: {
          _id: null,
          totalReports: { $sum: 1 },
          totalFileSize: { $sum: '$filesize' },
          avgFileSize: { $avg: '$filesize' }
        }
      }
    ]).toArray();
    
    const currentStats = currentMonthStats[0] || { totalReports: 0, totalFileSize: 0, avgFileSize: 0 };
    const lastStats = lastMonthStats[0] || { totalReports: 0, totalFileSize: 0, avgFileSize: 0 };
    
    // Calculate percentage changes
    const reportGrowth = lastStats.totalReports > 0 
      ? ((currentStats.totalReports - lastStats.totalReports) / lastStats.totalReports * 100).toFixed(1)
      : '0';
    
    const sizeGrowth = lastStats.totalFileSize > 0 
      ? ((currentStats.totalFileSize - lastStats.totalFileSize) / lastStats.totalFileSize * 100).toFixed(1)
      : '0';
    
    const avgSizeGrowth = lastStats.avgFileSize > 0 
      ? ((currentStats.avgFileSize - lastStats.avgFileSize) / lastStats.avgFileSize * 100).toFixed(1)
      : '0';
    
    // Get report type distribution
    const reportTypes = await collection.aggregate([
      {
        $match: {
          raisedat: {
            $gte: currentMonthStart,
            $lte: currentMonthEnd
          }
        }
      },
      {
        $group: {
          _id: '$description',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 5
      }
    ]).toArray();
    
    res.json({
      status: 'success',
      data: {
        totalReports: await collection.countDocuments({}),
        thisMonth: currentStats.totalReports,
        activeUsers: await collection.distinct('userid').then(users => users.length),
        monthlyGrowth: parseFloat(reportGrowth),
        totalGrowth: 15.5,
        overview: {
          totalReports: currentStats.totalReports,
          reportGrowth: reportGrowth,
          totalFileSize: currentStats.totalFileSize,
          sizeGrowth: sizeGrowth,
          avgFileSize: Math.round(currentStats.avgFileSize || 0),
          avgSizeGrowth: avgSizeGrowth,
          activeMimeTypes: ['image/jpeg', 'image/png', 'application/pdf', 'text/csv']
        },
        reportTypes: reportTypes,
        monthlyTrend: {
          current: currentStats.totalReports,
          previous: lastStats.totalReports,
          growth: reportGrowth
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch statistics',
      error: error.message
    });
  }
});

// Get reports by specific user
router.get('/user/:userId', async (req, res) => {
  try {
    const database = await initDB();
    const collection = database.collection(COLLECTION_NAME);
    const { userId } = req.params;
    
    const reports = await collection
      .find(
        { userid: userId },
        {
          projection: {
            userid: 1,
            description: 1,
            imageurl: 1,
            s3Key: 1,
            raisedat: 1,
            location: 1,
            filename: 1,
            filesize: 1,
            mimetype: 1
          }
        }
      )
      .sort({ raisedat: -1 })
      .toArray();

    // Transform reports to match frontend expectations
    const transformedReports = reports.map(report => ({
      ...report,
      imageurl: report.s3Key || report.imageurl,
      location: report.location || 'Unknown Location'
    }));
    
    res.json({
      status: 'success',
      data: transformedReports
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch user reports',
      error: error.message
    });
  }
});

// Generate signed URL for S3 image access
router.get('/image/:s3Key(*)', async (req, res) => {
  try {
    const { s3Key } = req.params;
    
    // Handle the s3Key which might contain forward slashes
    const fullKey = decodeURIComponent(s3Key);
    
    // Generate signed URL that expires in 1 hour using AWS SDK v3
    const command = new GetObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET_NAME || 'myclimate789',
      Key: fullKey
    });
    
    const signedUrl = await getSignedUrl(s3Client, command, {
      expiresIn: 3600 // 1 hour
    });
    
    res.json({
      status: 'success',
      data: {
        signedUrl: signedUrl,
        expiresIn: 3600,
        s3Key: fullKey
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to generate signed URL',
      error: error.message
    });
  }
});

// Delete report endpoint
router.delete('/:reportId', async (req, res) => {
  try {
    const database = await initDB();
    const collection = database.collection(COLLECTION_NAME);
    const { reportId } = req.params;
    
    // Validate ObjectId
    if (!ObjectId.isValid(reportId)) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid report ID format'
      });
    }
    
    // Delete the report
    const result = await collection.deleteOne({ _id: new ObjectId(reportId) });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({
        status: 'error',
        message: 'Report not found'
      });
    }
    
    res.json({
      status: 'success',
      message: 'Report deleted successfully',
      data: {
        deletedId: reportId,
        deletedCount: result.deletedCount
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete report',
      error: error.message
    });
  }
});

// Health check endpoint
router.get('/health', async (req, res) => {
  try {
    const database = await initDB();
    const collection = database.collection(COLLECTION_NAME);
    
    // Test MongoDB connection
    const testQuery = await collection.countDocuments({});
    
    res.json({
      status: 'success',
      data: {
        status: 'healthy',
        database: 'connected',
        totalDocuments: testQuery,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Health check failed',
      error: error.message
    });
  }
});

module.exports = router;