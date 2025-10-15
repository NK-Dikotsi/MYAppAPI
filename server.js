const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const fetch = require('node-fetch');
const { connect } = require('http2');
const crypto = require('crypto');
const http = require('http'); 
const { ExpressPeerServer } = require('peer');

const app = express();
//payload
app.use(express.json({ limit: '64mb' }));
app.use(express.urlencoded({ limit: '64mb', extended: true }));
app.use(cors());



/********************OCR & MESSAGE CHECK HELPERS********************* */
const { createWorker } = require('tesseract.js');
const { parse } = require('node-html-parser');

// Advertising detection keywords
const ADVERTISING_KEYWORDS = [
  'sale', 'offer', 'discount', 'promo', 'promotion', 'deal', 'bargain', 'cheap', 'free',
  'limited', 'exclusive', 'special', 'bonus', 'save', 'percent', '%', 'off', 'reduced',
  'clearance', 'liquidation', 'closing', 'must', 'now', 'today', 'hurry', 'act',
  'buy', 'purchase', 'order', 'shop', 'store', 'market', 'business', 'company',
  'service', 'product', 'brand', 'quality', 'professional', 'certified', 'licensed',
  'guaranteed', 'warranty', 'insurance', 'investment', 'loan', 'credit', 'finance',
  'call', 'contact', 'visit', 'click', 'subscribe', 'join', 'register', 'sign',
  'download', 'install', 'get', 'claim', 'win', 'earn', 'make', 'money', 'cash',
  'prize', 'reward', 'gift', 'voucher', 'coupon', 'code',
  'new', 'latest', 'best', 'top', 'premium', 'luxury', 'ultimate', 'amazing',
  'incredible', 'fantastic', 'excellent', 'perfect', 'unique', 'revolutionary',
  'breakthrough', 'advanced', 'innovative', 'cutting-edge', 'state-of-the-art',
  'urgent', 'immediate', 'instant', 'quick', 'fast', 'rush', 'asap', 'deadline',
  'expires', 'limited time', 'while supplies', 'first come', 'don\'t miss',
  'repair', 'maintenance', 'cleaning', 'delivery', 'shipping', 'installation',
  'consultation', 'quote', 'estimate', 'appointment', 'booking', 'reservation'
];

// Patterns for contact information
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
const PHONE_PATTERN = /(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/g;
const URL_PATTERN = /(https?:\/\/[^\s]+|www\.[^\s]+)/g;

// Create a reusable worker instance
let workerInstance = null;
let workerPromise = null;

async function getWorker() {
  if (workerInstance) {
    return workerInstance;
  }

  if (workerPromise) {
    return workerPromise;
  }

  workerPromise = (async () => {
    try {
      // Simplified worker creation for Render.com compatibility
      const worker = await createWorker('eng', 1, {
        logger: m => console.log('OCR:', m),
        errorHandler: err => console.error('OCR Error:', err)
      });

      workerInstance = worker;
      return worker;
    } catch (error) {
      console.error('Failed to create OCR worker:', error);
      workerPromise = null;
      throw error;
    }
  })();

  return workerPromise;
}

async function performOCR(imageBase64) {
  let worker = null;

  try {
    console.log('Starting OCR processing...');
    worker = await getWorker();

    // Convert base64 to buffer if needed
    const imageData = `data:image/jpeg;base64,${imageBase64}`;

    console.log('OCR worker ready, processing image...');
    const { data: { text, confidence } } = await worker.recognize(imageData, {
      rectangles: [], // Process entire image
    });

    const cleanText = text.trim().replace(/\s+/g, ' ');
    console.log(`OCR completed with confidence: ${confidence}%, extracted: "${cleanText.substring(0, 100)}${cleanText.length > 100 ? '...' : ''}"`);

    // Only return text if confidence is reasonable
    if (confidence < 30) {
      console.log('OCR confidence too low, skipping text analysis');
      return '';
    }

    return cleanText;
  } catch (error) {
    console.error('OCR processing failed:', error);

    // Reset worker on error
    if (workerInstance) {
      try {
        await workerInstance.terminate();
      } catch (termErr) {
        console.error('Error terminating worker:', termErr);
      }
      workerInstance = null;
      workerPromise = null;
    }

    throw new Error(`OCR failed: ${error.message}`);
  }
}

function analyzeTextForAdvertising(text) {
  if (!text || typeof text !== 'string') {
    return { isAdvertising: false, detectedWords: [], contactInfo: [], score: 0 };
  }

  // Clean and normalize the text
  const cleanText = text.replace(/[^\w\s@.-]/g, ' ').replace(/\s+/g, ' ').trim();
  const lowerText = cleanText.toLowerCase();

  console.log('Analyzing text:', cleanText.substring(0, 100) + (cleanText.length > 100 ? '...' : ''));

  // Check for advertising keywords (case-insensitive)
  const detectedAdWords = ADVERTISING_KEYWORDS.filter(keyword => {
    const keywordLower = keyword.toLowerCase();
    // Use word boundaries to avoid partial matches
    const regex = new RegExp(`\\b${keywordLower}\\b`, 'i');
    return regex.test(lowerText);
  });

  console.log('Detected ad words:', detectedAdWords);

  // Check for contact information
  const emails = text.match(EMAIL_PATTERN) || [];
  const phones = text.match(PHONE_PATTERN) || [];
  const urls = text.match(URL_PATTERN) || [];

  const contactInfo = [...emails, ...phones, ...urls];
  const hasContactInfo = contactInfo.length > 0;

  console.log('Contact info found:', contactInfo);

  // Scoring system for better detection
  let score = 0;

  // Base score for advertising keywords
  score += detectedAdWords.length * 15;

  // Bonus for contact info + keywords
  if (hasContactInfo && detectedAdWords.length > 0) {
    score += 30;
  }

  // Bonus for multiple contact methods
  if (contactInfo.length > 1) {
    score += 20;
  }

  // Check for common advertising phrases
  const adPhrases = [
    'limited time', 'act now', 'don\'t miss', 'call now', 'visit our',
    'best price', 'lowest price', 'money back', 'satisfaction guaranteed',
    'free shipping', 'no obligation', 'risk free', 'special offer',
    'huge discount', 'save money', 'get cash', 'earn money'
  ];

  const detectedPhrases = adPhrases.filter(phrase =>
    lowerText.includes(phrase.toLowerCase())
  );

  score += detectedPhrases.length * 25;

  console.log(`Analysis complete: score=${score}, keywords=${detectedAdWords.length}, phrases=${detectedPhrases.length}, contact=${contactInfo.length}`);

  const isAdvertising = score >= 20; // Lowered threshold for more sensitive detection

  return {
    isAdvertising,
    detectedWords: [...new Set(detectedAdWords)],
    detectedPhrases,
    contactInfo,
    score
  };
}

async function checkMessageForAds(content, imageBase64) {
  let reasons = [];
  let totalScore = 0;

  try {
    console.log('=== Starting Message Analysis ===');

    // Check text content
    if (content && content.trim()) {
      console.log('Analyzing text content...');
      const textAnalysis = analyzeTextForAdvertising(content);
      totalScore += textAnalysis.score;

      if (textAnalysis.isAdvertising) {
        const details = [];
        if (textAnalysis.detectedWords.length > 0) {
          details.push(`keywords: ${textAnalysis.detectedWords.join(', ')}`);
        }
        if (textAnalysis.detectedPhrases.length > 0) {
          details.push(`phrases: ${textAnalysis.detectedPhrases.join(', ')}`);
        }
        if (textAnalysis.contactInfo.length > 0) {
          details.push(`contact info detected`);
        }

        reasons.push(`Advertising Text Identified - ${details.join('; ')}`);
        console.log(`Text flagged with score: ${textAnalysis.score}`);
      } else {
        console.log(`Text passed with score: ${textAnalysis.score}`);
      }
    }

    // Check image if exists
    if (imageBase64) {
      try {
        console.log('Starting OCR analysis...');
        const ocrText = await performOCR(imageBase64);

        if (ocrText && ocrText.trim().length > 0) {
          console.log('Analyzing OCR extracted text...');
          const imageAnalysis = analyzeTextForAdvertising(ocrText);
          totalScore += imageAnalysis.score;

          if (imageAnalysis.isAdvertising) {
            const details = [];
            if (imageAnalysis.detectedWords.length > 0) {
              details.push(`keywords: ${imageAnalysis.detectedWords.join(', ')}`);
            }
            if (imageAnalysis.detectedPhrases.length > 0) {
              details.push(`phrases: ${imageAnalysis.detectedPhrases.join(', ')}`);
            }
            if (imageAnalysis.contactInfo.length > 0) {
              details.push(`contact info detected`);
            }

            reasons.push(`Image Advertising identified  - ${details.join('; ')} - OCR text: "${ocrText.substring(0, 50)}${ocrText.length > 50 ? '...' : ''}"`);
            console.log(`Image flagged with score: ${imageAnalysis.score}`);
          } else {
            console.log(`Image passed with score: ${imageAnalysis.score}`);
          }
        } else {
          console.log('No meaningful text extracted from image');
        }
      } catch (ocrError) {
        console.error('OCR analysis failed:', ocrError);
        // Don't penalize for OCR failure, but log it
        console.log('Continuing analysis without image text due to OCR failure');
      }
    }

    // Lower threshold for flagging - more sensitive
    const shouldFlag = totalScore >= 20;

    console.log(`=== Analysis Complete ===`);
    console.log(`Total Score: ${totalScore}`);
    console.log(`Should Flag: ${shouldFlag}`);
    console.log(`Reasons: ${reasons.join(' | ') || 'No violations detected'}`);

    return {
      shouldFlag,
      reasons: reasons.length > 0 ? reasons.join(' | ') : 'No advertising detected',
      totalScore
    };

  } catch (error) {
    console.error('Message analysis error:', error);
    return {
      shouldFlag: false,
      reasons: `Analysis error: ${error.message}`,
      totalScore: 0
    };
  }
}

async function cleanup() {
  if (workerInstance) {
    try {
      await workerInstance.terminate();
      console.log('OCR worker terminated successfully');
    } catch (error) {
      console.error('Error terminating OCR worker:', error);
    }
    workerInstance = null;
    workerPromise = null;
  }
}

// Handle process termination
process.on('SIGTERM', cleanup);
process.on('SIGINT', cleanup);
process.on('exit', cleanup);

module.exports = {
  checkMessageForAds,
  analyzeTextForAdvertising,
  performOCR,
  cleanup
};


const session = require('express-session');
const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.use(session({
  secret: 'cookie-123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Should be true in production with HTTPS
    sameSite: 'lax', // Add this for cross-site cookies
    maxAge: 24 * 60 * 60 * 1000
  },
  store: new session.MemoryStore() // Explicitly declare store
}));


// SQL Server Configuration - New Config
const config = {
  server: process.env.DB_SERVER || 'siza.database.windows.net',
  user: process.env.DB_USER || 'sizaadmin',
  password: process.env.DB_PASSWORD || 'Ntsane@20031225',
  database: 'siza',
  options: { encrypt: true }
};


/*const config = {
  server: process.env.DB_SERVER || 'projectsdayserver.database.windows.net',
  user: process.env.DB_USER || 'sizaadmin',
  password: process.env.DB_PASSWORD || 'Ntsane@20031225',
  database: 'projectsdaydatabase',
  options: { encrypt: true }
};*/

app.use(cors({
  origin: true, // Or true for all origins
  credentials: true, // Important for sessions
  methods: ['GET', 'POST', 'OPTIONS']
}));


// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session?.user?.id) { // Updated to match your session structure
    return res.status(401).json({
      success: false,
      message: 'Unauthorized - Please login again'
    });
  }
  next();
};

app.use(express.json());
app.use(cors());

// =============================================================================
// CREATE HTTP SERVER (ONCE)
// =============================================================================
const server = http.createServer(app);

// =============================================================================
// PEERJS SERVER SETUP
// =============================================================================
const peerServer = ExpressPeerServer(server, {
  debug: true,
  path: '/peerjs',
  proxied: true,
  allow_discovery: true
});

app.use('/peerjs', peerServer);

// PeerJS server events
peerServer.on('connection', (client) => {
  console.log(`✅ Peer connected: ${client.getId()}`);
});

peerServer.on('disconnect', (client) => {
  console.log(`❌ Peer disconnected: ${client.getId()}`);
});

peerServer.on('error', (error) => {
  console.error('❌ PeerJS server error:', error);
});

// =============================================================================
// PEERJS CONFIGURATION
// =============================================================================
const PEERJS_CONFIG = {
  host: 'myappapi-yo3p.onrender.com',
  port: 443,
  secure: true,
  path: '/peerjs'
};

// Generate unique room name for SOS report
function generatePeerJSRoom(reportId) {
  const timestamp = Date.now();
  const randomSuffix = Math.random().toString(36).substring(2, 8);
  const roomName = `sos-${reportId}-${timestamp}-${randomSuffix}`;
  
  return {
    roomName,
    peerConfig: PEERJS_CONFIG
  };
}

// Create PeerJS room in database
async function createPeerJSRoomInDB(reportId, createdBy = null) {
  let pool;
  try {
    const roomInfo = generatePeerJSRoom(reportId);
    
    pool = await sql.connect(config);
    const result = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .input('RoomName', sql.VarChar, roomInfo.roomName)
      .input('Status', sql.VarChar, 'active')
      .input('CreatedBy', sql.Int, createdBy)
      .query(`
        INSERT INTO Room (ReportId, RoomName, Status, CreatedBy)
        OUTPUT INSERTED.RoomId
        VALUES (@ReportId, @RoomName, @Status, @CreatedBy)
      `);

    const roomId = result.recordset[0].RoomId;
    
    console.log(`✓ PeerJS room created for report ${reportId}: ${roomInfo.roomName}`);
    return {
      roomId,
      ...roomInfo
    };
  } catch (error) {
    console.error('Error creating PeerJS room in DB:', error);
    throw error;
  } finally {
    if (pool) {
      await pool.close();
    }
  }
}

// =============================================================================
// PEERJS ENDPOINTS
// =============================================================================

// Create PeerJS room for SOS report
app.post('/api/peerjs/create-after-report', async (req, res) => {
  console.log('📞 Creating PeerJS room for report:', req.body);
  
  const { reportId, userId, emergencyType } = req.body;
  let pool;

  try {
    // Validate input
    if (!reportId || !userId || !emergencyType) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: reportId, userId, emergencyType'
      });
    }

    if (emergencyType !== 'SOS') {
      return res.json({
        success: false,
        message: 'PeerJS rooms only available for SOS reports'
      });
    }

    pool = await sql.connect(config);
    
    // Check if room exists
    const existingRoom = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query(`
        SELECT RoomId, RoomName, Status 
        FROM Room 
        WHERE ReportId = @ReportId AND Status = 'active'
      `);

    if (existingRoom.recordset.length > 0) {
      const room = existingRoom.recordset[0];
      console.log(`✓ Room already exists for report ${reportId}: ${room.RoomName}`);
      return res.json({
        success: true,
        roomCreated: false,
        roomId: room.RoomId,
        roomName: room.RoomName,
        peerConfig: PEERJS_CONFIG,
        message: 'Room already exists'
      });
    }

    // Create new room
    const roomData = await createPeerJSRoomInDB(reportId, userId);
    
    console.log(`✅ Successfully created PeerJS room for report ${reportId}`);

    res.json({
      success: true,
      roomCreated: true,
      roomId: roomData.roomId,
      roomName: roomData.roomName,
      peerConfig: roomData.peerConfig
    });

  } catch (error) {
    console.error('❌ Create PeerJS room error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to create PeerJS room: ' + error.message
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Get PeerJS room info
app.get('/api/peerjs/room', async (req, res) => {
  const { reportId } = req.query;
  let pool;

  try {
    if (!reportId) {
      return res.status(400).json({ 
        success: false, 
        message: 'reportId is required' 
      });
    }

    pool = await sql.connect(config);
    const result = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query(`
        SELECT RoomId, RoomName, Status
        FROM Room 
        WHERE ReportId = @ReportId AND Status = 'active'
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'No active PeerJS room found' 
      });
    }

    const room = result.recordset[0];
    
    res.json({
      success: true,
      roomId: room.RoomId,
      roomName: room.RoomName,
      peerConfig: PEERJS_CONFIG
    });

  } catch (error) {
    console.error('PeerJS room fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch PeerJS room' 
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Join room
app.post('/api/peerjs/join', async (req, res) => {
  const { roomId, userId } = req.body;
  let pool;

  try {
    if (!roomId || !userId) {
      return res.status(400).json({
        success: false,
        message: 'roomId and userId are required'
      });
    }

    pool = await sql.connect(config);
    
    const result = await pool.request()
      .input('RoomId', sql.Int, roomId)
      .input('UserId', sql.Int, userId)
      .query(`
        INSERT INTO RoomParticipant (RoomId, UserId)
        OUTPUT INSERTED.RoomParticipantId
        VALUES (@RoomId, @UserId)
      `);

    const participantId = result.recordset[0].RoomParticipantId;
    console.log(`✓ User ${userId} joined PeerJS room ${roomId}`);

    res.json({
      success: true,
      participantId: participantId
    });

  } catch (error) {
    console.error('Join PeerJS room error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to join room'
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Leave room
app.post('/api/peerjs/leave', async (req, res) => {
  const { roomId, userId } = req.body;
  let pool;

  try {
    if (!roomId || !userId) {
      return res.status(400).json({
        success: false,
        message: 'roomId and userId are required'
      });
    }

    pool = await sql.connect(config);
    
    await pool.request()
      .input('RoomId', sql.Int, roomId)
      .input('UserId', sql.Int, userId)
      .query(`
        UPDATE RoomParticipant
        SET LeftAt = dbo.GetSASTDateTime()
        WHERE RoomParticipantId IN (
          SELECT TOP 1 RoomParticipantId
          FROM RoomParticipant
          WHERE RoomId = @RoomId AND UserId = @UserId AND LeftAt IS NULL
          ORDER BY JoinedAt DESC
        )
      `);

    console.log(`✓ User ${userId} left PeerJS room ${roomId}`);

    res.json({
      success: true,
      message: 'Left room successfully'
    });

  } catch (error) {
    console.error('Leave PeerJS room error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to leave room'
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});


// Add this test endpoint to verify the server is working
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Server is working!',
    timestamp: new Date().toISOString()
  });
});

// =============================================================================
// SERVER STARTUP
// =============================================================================
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ PeerJS server running on /peerjs`);
  console.log(`✅ Test endpoint: https://myappapi-yo3p.onrender.com/api/test`);
});



// Registration Endpoint
app.post('/register', async (req, res) => {
  const { fullName, email, password, phoneNumber, role, dob, homeAddress, imageBase64, gender } = req.body;
  const Username = email.split("@")[0];
  const userType = 'CommunityMember';
  const acceptedTerms = 'Yes'; // Assuming they accept terms during registration

  try {
    const pool = await sql.connect(config);

    // Insert user with SAST timestamp
    const usersResult = await pool.request()
      .input('FullName', sql.VarChar, fullName)
      .input('Email', sql.VarChar, email)
      .input('Username', sql.VarChar, Username)
      .input('PhoneNumber', sql.VarChar, phoneNumber)
      .input('Passcode', sql.VarChar, password)
      .input('UserType', sql.VarChar, userType)
      .input('ProfilePhoto', sql.VarChar, imageBase64)
      .input('AcceptedTerms', sql.VarChar, acceptedTerms)
      .input('Gender', sql.VarChar, gender || 'Prefer not to say')
      .query(`
        INSERT INTO [dbo].[Users]
        (FullName, Email, Username, PhoneNumber, Passcode, UserType, CreatedAt, ProfilePhoto, AcceptedTerms, Gender)
        OUTPUT INSERTED.UserID
        VALUES
        (@FullName, @Email, @Username, @PhoneNumber, @Passcode, @UserType, 
         dbo.GetSASTDateTime(), @ProfilePhoto, @AcceptedTerms, @Gender)
      `);

    const userID = usersResult.recordset[0].UserID;

    if (userType === 'CommunityMember') {
      await pool.request()
        .input('UserID', sql.Int, userID)
        .input('Role', sql.VarChar, role)
        .input('DOB', sql.Date, dob)
        .input('HomeAddress', sql.VarChar, homeAddress)
        .input('TrustedContacts', sql.VarChar, '0') // Initialize with 0 trusted contacts
        .query(`
          INSERT INTO [dbo].[CommunityMember]
          (UserID, Role, DOB, HomeAddress, TrustedContacts)
          VALUES
          (@UserID, @Role, @DOB, @HomeAddress, @TrustedContacts) 
        `);
    }

    res.status(201).json({
      message: 'User registered successfully.',
      userID: userID
    });
  }
  catch (err) {
    console.error('Registration error:', err);

    // More specific error handling
    if (err.number === 2627) { // SQL Server duplicate key error
      return res.status(409).json({ message: 'Email already exists.' });
    }

    res.status(500).json({ message: 'Internal server error.' });
  }
});

app.put('/acceptTerms', async (req, res) => {
  const { userID } = req.body;

  if (!userID) {
    return res.status(400).json({ success: false, message: 'UserID is required.' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.BigInt, userID)
      .query(`
                UPDATE [dbo].[Users]
                SET AcceptedTerms = 'Yes'
                WHERE UserID = @UserID
            `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ success: false, message: 'No user found with the provided ID.' });
    }

    res.status(200).json({ success: true, message: 'Terms accepted successfully.' });
  } catch (err) {
    console.error('Error accepting terms:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


app.use(express.json());
app.use(cors());

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('Email', sql.VarChar, email)
      .input('Password', sql.VarChar, password)
      .query(`
                SELECT UserID, FullName, Email, UserType 
                FROM [dbo].[Users] 
                WHERE Email = @Email AND Passcode = @Password
            `);

    if (result.recordset.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const user = result.recordset[0];
    // Store user in session
    req.session.user = {
      id: user.UserID,
      email: user.Email,
      role: user.UserType
    };

    res.status(200).json({
      success: true,
      message: 'Login successful!',
      user: {
        id: user.UserID,
        name: user.FullName,
        email: user.Email,
        role: user.UserType,
      }

    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


app.get('/getReports', async (req, res) => {
  const userId = parseInt(req.query.userId);
  console.log(userId);

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ message: 'Missing or invalid userId.' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query('SELECT * FROM [dbo].[Report] WHERE ReporterID = @UserID');

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'No reports found for this user.' });
    }

    res.status(200).json({ success: true, reports: result.recordset });
  } catch (err) {
    console.error('Error fetching reports by userId:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});
app.get('/analytics/getReports', async (req, res) => {
  const userId = parseInt(req.query.userId);
  console.log(userId);

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ message: 'Missing or invalid userId.' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT 
          ReportID,
          ReporterID,
          emergencyType,
          emerDescription,
          sharedWith,
          Report_Location,
          Report_Status,
          dateReported,
          suburbName
        FROM [dbo].[Report]
        WHERE ReporterID = @UserID
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'No reports found for this user.' });
    }

    res.status(200).json({ success: true, reports: result.recordset });
  } catch (err) {
    console.error('Error fetching analytics reports by userId:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


app.put('/updateUser', async (req, res) => {
  const { userID, fullName, phoneNumber, username, dob, homeAddress, imageBase64, gender } = req.body;

  try {
    const pool = await sql.connect(config);

    // Update Users table
    await pool.request()
      .input('UserID', sql.BigInt, userID)
      .input('FullName', sql.VarChar, fullName)
      .input('Username', sql.VarChar, username)
      .input('PhoneNumber', sql.VarChar, phoneNumber)
      .input('ProfilePhoto', sql.VarChar, imageBase64)
      .input('Gender', sql.VarChar, gender)
      .query(`
                UPDATE [dbo].[Users]
                SET FullName = @FullName,
                    Username = @Username,
                    PhoneNumber = @PhoneNumber,
                    ProfilePhoto = @ProfilePhoto,
                    Gender = @Gender
                WHERE UserID = @UserID
            `);

    // Update CommunityMember table
    await pool.request()
      .input('UserID', sql.BigInt, userID)
      .input('DOB', sql.Date, dob)
      .input('HomeAddress', sql.VarChar, homeAddress)
      .query(`
                UPDATE [dbo].[CommunityMember]
                SET DOB = @DOB,
                    HomeAddress = @HomeAddress
                WHERE UserID = @UserID
            `);

    res.status(200).json({ message: 'User updated successfully.' });

  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});


// Jitsi configuration


const JITSI_DOMAIN = "meet.jit.si";

// Generate Jitsi room name for SOS report
function generateJitsiRoom(reportId) {
  const timestamp = Date.now();
  const randomSuffix = Math.random().toString(36).substring(2, 8);
  const roomName = `sos-${reportId}-${timestamp}-${randomSuffix}`;
  
  return {
    roomName,
    roomUrl: `https://${JITSI_DOMAIN}/${roomName}`,
    domain: JITSI_DOMAIN
  };
}

// Generate Jitsi room URL with LEGITIMATE configuration
function generateJitsiRoomUrl(roomName, userName = 'User', isVideoEnabled = true) {
  // LEGITIMATE configuration using only supported parameters
  const jitsiConfig = {
    // Room behavior - LEGITIMATE PARAMETERS
    'config.startWithAudioMuted': 'false',
    'config.startWithVideoMuted': isVideoEnabled ? 'false' : 'true',
    'config.prejoinPageEnabled': 'false',

    // UI simplification (legitimate)
    'config.enableWelcomePage': 'false',
    'config.requireDisplayName': 'false',
    'config.disableProfile': 'false',

    // Audio/Video defaults
    'config.enableNoAudioDetection': 'false',
    'config.enableNoisyMicDetection': 'true',

    // Toolbar for emergency scenarios (minimal but functional)
    'config.toolbarButtons': JSON.stringify([
      'microphone',
      'camera',
      'closedcaptions',
      'desktop',
      'fullscreen',
      'fodeviceselection',
      'hangup',
      'chat',
      'raisehand',
      'settings',
      'shortcuts'
    ]),

    // User info
    'userInfo.displayName': userName,
    'userInfo.email': '',

    // Connection settings
    'config.disableAudioLevels': 'false',
    'config.channelLastN': '-1',
  };

  // Build URL with config parameters
  const params = new URLSearchParams();
  Object.entries(jitsiConfig).forEach(([key, value]) => {
    params.append(key, value);
  });

  return `https://${JITSI_DOMAIN}/${roomName}#${params.toString()}`;
}

// Create Jitsi room in database for SOS report
async function createJitsiRoomInDB(reportId, createdBy = null) {
  let pool;
  try {
    const roomInfo = generateJitsiRoom(reportId);
    
    pool = await sql.connect(config);
    const result = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .input('RoomName', sql.VarChar, roomInfo.roomName)
      .input('Status', sql.VarChar, 'active')
      .input('CreatedBy', sql.Int, createdBy)
      .query(`
        INSERT INTO Room (ReportId, RoomName, Status, CreatedBy)
        OUTPUT INSERTED.RoomId
        VALUES (@ReportId, @RoomName, @Status, @CreatedBy)
      `);

    const roomId = result.recordset[0].RoomId;
    
    console.log(`✓ Jitsi room created in DB for report ${reportId}:`, roomInfo.roomName);
    console.log(`  Room ID: ${roomId}`);
    console.log(`  Room URL: ${roomInfo.roomUrl}`);

    return {
      roomId,
      ...roomInfo
    };
  } finally {
    if (pool) {
      await pool.close();
    }
  }
}

// NEW ENDPOINT: Auto-create Jitsi room for SOS reports (LEGITIMATE)
app.post('/api/jitsi/auto-create-room', async (req, res) => {
  const { reportId, userId, emergencyType } = req.body;
  let pool;

  try {
    // Only create rooms for SOS reports
    if (emergencyType !== 'SOS') {
      return res.json({
        success: false,
        message: 'Jitsi rooms only available for SOS reports',
        roomCreated: false
      });
    }

    // Check if room already exists for this report
    pool = await sql.connect(config);
    const existingRoom = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query(`
        SELECT RoomId, RoomName, Status 
        FROM Room 
        WHERE ReportId = @ReportId AND Status = 'active'
      `);

    if (existingRoom.recordset.length > 0) {
      const room = existingRoom.recordset[0];
      const roomUrl = generateJitsiRoomUrl(room.RoomName, 'Reporter');
      
      return res.json({
        success: true,
        roomCreated: false,
        roomId: room.RoomId,
        roomName: room.RoomName,
        roomUrl: roomUrl,
        domain: JITSI_DOMAIN,
        message: 'Room already exists'
      });
    }

    // Create new room
    const roomData = await createJitsiRoomInDB(reportId, userId);
    const roomUrl = generateJitsiRoomUrl(roomData.roomName, 'Reporter');

    console.log(`✓ Auto-created Jitsi room for SOS report ${reportId}`);
    console.log(`  Legitimate configuration applied`);

    res.json({
      success: true,
      roomCreated: true,
      roomId: roomData.roomId,
      roomName: roomData.roomName,
      roomUrl: roomUrl,
      domain: roomData.domain,
      configuration: 'legitimate'
    });

  } catch (error) {
    console.error('Auto-create room error:', error);
    res.status(500).json({ 
      success: false,
      roomCreated: false,
      message: 'Failed to auto-create Jitsi room' 
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Get Jitsi room for report with LEGITIMATE configuration
app.get('/api/jitsi/room', async (req, res) => {
  const { reportId, userName = 'User', isVideoEnabled = 'true' } = req.query;
  let pool;

  try {
    pool = await sql.connect(config);
    const result = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query(`
        SELECT RoomId, RoomName, Status, CreatedAt, EndedAt, CreatedBy
        FROM Room 
        WHERE ReportId = @ReportId AND Status = 'active'
      `);

    if (result.recordset.length === 0) {
      console.log(`✗ No active Jitsi room found for report ${reportId}`);
      return res.status(404).json({ 
        success: false, 
        message: 'No active Jitsi room found for this report' 
      });
    }

    const room = result.recordset[0];
    console.log(`✓ Jitsi room found for report ${reportId}:`, room.RoomName);

    // Generate room URL with legitimate configuration
    const videoEnabled = isVideoEnabled === 'true';
    const roomUrl = generateJitsiRoomUrl(room.RoomName, userName, videoEnabled);

    res.json({
      success: true,
      roomId: room.RoomId,
      roomName: room.RoomName,
      roomUrl: roomUrl,
      domain: JITSI_DOMAIN,
      status: room.Status,
      createdAt: room.CreatedAt,
      createdBy: room.CreatedBy,
      configuration: 'legitimate'
    });

  } catch (error) {
    console.error('Jitsi room fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch Jitsi room' 
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Generate room for SOS report (manual creation - LEGITIMATE)
app.post('/api/jitsi/generate-room', async (req, res) => {
  const { reportId, emergencyType, userId, userName } = req.body;
  let pool;

  try {
    // Only generate rooms for SOS reports
    if (emergencyType !== 'SOS') {
      return res.status(400).json({ 
        success: false, 
        message: 'Jitsi rooms only available for SOS reports' 
      });
    }

    // Check if room already exists for this report
    pool = await sql.connect(config);
    const existingRoom = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query(`
        SELECT RoomId, RoomName, Status 
        FROM Room 
        WHERE ReportId = @ReportId AND Status = 'active'
      `);

    if (existingRoom.recordset.length > 0) {
      const room = existingRoom.recordset[0];
      const roomUrl = generateJitsiRoomUrl(room.RoomName, userName || 'User');
      
      return res.json({
        success: true,
        roomId: room.RoomId,
        roomName: room.RoomName,
        roomUrl: roomUrl,
        domain: JITSI_DOMAIN,
        message: 'Room already exists'
      });
    }

    // Create new room
    const roomData = await createJitsiRoomInDB(reportId, userId);
    const roomUrl = generateJitsiRoomUrl(roomData.roomName, userName || 'User');

    res.json({
      success: true,
      roomId: roomData.roomId,
      roomName: roomData.roomName,
      roomUrl: roomUrl,
      domain: roomData.domain,
      configuration: 'legitimate'
    });

  } catch (error) {
    console.error('Jitsi room generation error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to generate Jitsi room' 
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Join Jitsi room (record participant) - UNCHANGED
app.post('/api/jitsi/join', async (req, res) => {
  const { roomId, userId } = req.body;
  let pool;

  try {
    pool = await sql.connect(config);
    
    // Check if user already joined and didn't leave
    const existingParticipant = await pool.request()
      .input('RoomId', sql.Int, roomId)
      .input('UserId', sql.Int, userId)
      .query(`
        SELECT RoomParticipantId, LeftAt
        FROM RoomParticipant
        WHERE RoomId = @RoomId AND UserId = @UserId
        ORDER BY JoinedAt DESC
      `);

    // If user is already in the room (hasn't left), don't create duplicate entry
    if (existingParticipant.recordset.length > 0 && 
        existingParticipant.recordset[0].LeftAt === null) {
      return res.json({
        success: true,
        message: 'User already in room',
        participantId: existingParticipant.recordset[0].RoomParticipantId
      });
    }

    // Record new join
    const result = await pool.request()
      .input('RoomId', sql.Int, roomId)
      .input('UserId', sql.Int, userId)
      .query(`
        INSERT INTO RoomParticipant (RoomId, UserId)
        OUTPUT INSERTED.RoomParticipantId
        VALUES (@RoomId, @UserId)
      `);

    const participantId = result.recordset[0].RoomParticipantId;
    console.log(`✓ User ${userId} joined room ${roomId} (participant ID: ${participantId})`);

    res.json({
      success: true,
      participantId: participantId,
      message: 'Joined room successfully'
    });

  } catch (error) {
    console.error('Join room error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to join room'
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Leave Jitsi room (record participant leaving) - UNCHANGED
app.post('/api/jitsi/leave', async (req, res) => {
  const { roomId, userId } = req.body;
  let pool;

  try {
    pool = await sql.connect(config);
    
    // Update the latest participation record
    await pool.request()
      .input('RoomId', sql.Int, roomId)
      .input('UserId', sql.Int, userId)
      .query(`
        UPDATE RoomParticipant
        SET LeftAt = dbo.GetSASTDateTime()
        WHERE RoomParticipantId IN (
          SELECT TOP 1 RoomParticipantId
          FROM RoomParticipant
          WHERE RoomId = @RoomId AND UserId = @UserId AND LeftAt IS NULL
          ORDER BY JoinedAt DESC
        )
      `);

    console.log(`✓ User ${userId} left room ${roomId}`);

    res.json({
      success: true,
      message: 'Left room successfully'
    });

  } catch (error) {
    console.error('Leave room error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to leave room'
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Get room participants - UNCHANGED
app.get('/api/jitsi/participants', async (req, res) => {
  const { roomId } = req.query;
  let pool;

  try {
    pool = await sql.connect(config);
    const result = await pool.request()
      .input('RoomId', sql.Int, roomId)
      .query(`
        SELECT 
          rp.RoomParticipantId,
          rp.UserId,
          u.Username,
          u.firstName,
          u.lastName,
          rp.JoinedAt,
          rp.LeftAt,
          CASE WHEN rp.LeftAt IS NULL THEN 1 ELSE 0 END AS IsActive
        FROM RoomParticipant rp
        INNER JOIN Users u ON rp.UserId = u.UserID
        WHERE rp.RoomId = @RoomId
        ORDER BY rp.JoinedAt DESC
      `);

    res.json({
      success: true,
      participants: result.recordset
    });

  } catch (error) {
    console.error('Get participants error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get participants'
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Check report type and Jitsi availability - UPDATED with legitimate config
app.get('/api/report/type', async (req, res) => {
  const { reportId, userName = 'User' } = req.query;
  let pool;

  try {
    pool = await sql.connect(config);
    const result = await pool.request()
      .input('ReportID', sql.Int, reportId)
      .query(`
        SELECT 
          r.emergencyType, 
          r.Report_Status,
          rm.RoomId,
          rm.RoomName,
          rm.Status as RoomStatus
        FROM [dbo].[Report] r
        LEFT JOIN Room rm ON r.ReportID = rm.ReportId AND rm.Status = 'active'
        WHERE r.ReportID = @ReportID
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Report not found' 
      });
    }

    const report = result.recordset[0];
    const hasJitsiRoom = report.RoomId !== null;
    
    console.log(`Report ${reportId} type check: ${report.emergencyType}, Has Jitsi: ${hasJitsiRoom}`);
    
    let roomUrl = null;
    if (hasJitsiRoom) {
      roomUrl = generateJitsiRoomUrl(report.RoomName, userName);
    }
    
    res.json({
      success: true,
      emergencyType: report.emergencyType,
      reportStatus: report.Report_Status,
      hasJitsiRoom: hasJitsiRoom,
      ...(hasJitsiRoom && {
        roomId: report.RoomId,
        roomName: report.RoomName,
        roomUrl: roomUrl,
        configuration: 'legitimate'
      })
    });

  } catch (err) {
    console.error('Error fetching report type:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// ORIGINAL addReport ENDPOINT - COMPLETELY UNCHANGED
app.post('/addReport', async (req, res) => {
  const { reporterID, emergencyType, emerDescription, mediaPhoto, mediaVoice, sharedWith, reportLocation, reportStatus } = req.body;

  let suburbName = "Unknown"; // Default fallback
  let pool;

  try {
    // First, let's get the suburb name from coordinates
    if (reportLocation) {
      try {
        const { default: fetch } = await import("node-fetch");
        const [lat, lng] = reportLocation.split(";").map(v => v.trim());

        if (!lat || !lng || isNaN(parseFloat(lat)) || isNaN(parseFloat(lng))) {
          console.warn(`Invalid coordinates for new report: ${reportLocation}`);
          suburbName = "Unknown";
        } else {
          const url = `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lng}&format=json&addressdetails=1&zoom=18`;
          const response = await fetch(url, {
            headers: { "User-Agent": "SizaCommunityWatch/1.0" }
          });

          if (!response.ok) {
            throw new Error(`API responded with status: ${response.status}`);
          }

          const data = await response.json();
          const detectedSuburb = data.address?.suburb || data.address?.neighbourhood || null;

          if (detectedSuburb) {
            suburbName = detectedSuburb;
            console.log(`✓ New report suburb detected: ${suburbName}`);
          } else {
            console.log(`✗ No suburb found for coordinates: ${lat}, ${lng}`);
            suburbName = "Unknown";
          }
        }
      } catch (geocodingError) {
        console.error('Reverse geocoding failed:', geocodingError.message);
        suburbName = "Unknown";
      }
    }

    // Insert the report with the detected suburb
    pool = await sql.connect(config);
    const result = await pool.request()
      .input('ReporterID', sql.Int, reporterID)
      .input('EmergencyType', sql.VarChar, emergencyType)
      .input('EmerDescription', sql.VarChar, emerDescription)
      .input('MediaPhoto', sql.VarChar, mediaPhoto)
      .input('MediaVoice', sql.VarChar, mediaVoice)
      .input('SharedWith', sql.VarChar, sharedWith)
      .input('ReportLocation', sql.VarChar, reportLocation)
      .input('ReportStatus', sql.VarChar, reportStatus)
      .input('suburbName', sql.VarChar, suburbName)
      .query(`
        INSERT INTO [dbo].[Report]
        (ReporterID, emergencyType, emerDescription, media_Photo, media_Voice, sharedWith, Report_Location, Report_Status, dateReported, suburbName)
        OUTPUT INSERTED.ReportID
        VALUES
        (@ReporterID, @EmergencyType, @EmerDescription, @MediaPhoto, @MediaVoice, @SharedWith, @ReportLocation, @ReportStatus, dbo.GetSASTDateTime(), @suburbName)
      `);

    const insertedReportID = result.recordset[0].ReportID;
    console.log(`✓ Report ${insertedReportID} created successfully`);

    res.status(201).json({
      message: 'Report submitted successfully.',
      reportID: insertedReportID,
      suburbName: suburbName
    });

  } catch (err) {
    console.error('Add report error:', err);
    res.status(500).json({ message: 'Internal server error.' });
  } finally {
    // Ensure database connection is closed
    if (pool) {
      await pool.close();
    }
  }
});

// NEW ENDPOINT: Create Jitsi room after report creation (LEGITIMATE)
app.post('/api/jitsi/create-after-report', async (req, res) => {
  const { reportId, userId, emergencyType } = req.body;
  let pool;

  try {
    // Only create rooms for SOS reports
    if (emergencyType !== 'SOS') {
      return res.json({
        success: false,
        message: 'Jitsi rooms only available for SOS reports'
      });
    }

    // Check if report exists
    pool = await sql.connect(config);
    const reportCheck = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query('SELECT emergencyType FROM [dbo].[Report] WHERE ReportID = @ReportId');

    if (reportCheck.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    // Check if room already exists
    const existingRoom = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query(`
        SELECT RoomId, RoomName, Status 
        FROM Room 
        WHERE ReportId = @ReportId AND Status = 'active'
      `);

    if (existingRoom.recordset.length > 0) {
      const room = existingRoom.recordset[0];
      const roomUrl = generateJitsiRoomUrl(room.RoomName, 'Reporter');
      
      return res.json({
        success: true,
        roomId: room.RoomId,
        roomName: room.RoomName,
        roomUrl: roomUrl,
        domain: JITSI_DOMAIN,
        message: 'Room already exists'
      });
    }

    // Create new room
    const roomData = await createJitsiRoomInDB(reportId, userId);
    const roomUrl = generateJitsiRoomUrl(roomData.roomName, 'Reporter');

    console.log(`✓ Created Jitsi room after report creation for report ${reportId}`);

    res.json({
      success: true,
      roomId: roomData.roomId,
      roomName: roomData.roomName,
      roomUrl: roomUrl,
      domain: roomData.domain,
      configuration: 'legitimate'
    });

  } catch (error) {
    console.error('Create after report error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to create Jitsi room' 
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// End a Jitsi room - UNCHANGED
app.post('/api/jitsi/end-room', async (req, res) => {
  const { roomId } = req.body;
  let pool;

  try {
    pool = await sql.connect(config);
    
    // Update room status to ended
    await pool.request()
      .input('RoomId', sql.Int, roomId)
      .query(`
        UPDATE Room
        SET Status = 'ended', EndedAt = dbo.GetSASTDateTime()
        WHERE RoomId = @RoomId
      `);

    // Mark all active participants as left
    await pool.request()
      .input('RoomId', sql.Int, roomId)
      .query(`
        UPDATE RoomParticipant
        SET LeftAt = dbo.GetSASTDateTime()
        WHERE RoomId = @RoomId AND LeftAt IS NULL
      `);
    
    console.log(`✓ Jitsi room ${roomId} ended`);

    res.json({
      success: true,
      message: 'Room ended successfully'
    });

  } catch (error) {
    console.error('End room error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to end room'
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Get Jitsi room statistics - UPDATED with legitimate config
app.get('/api/jitsi/stats', async (req, res) => {
  let pool;

  try {
    pool = await sql.connect(config);
    const result = await pool.request()
      .query(`
        SELECT 
          r.RoomId,
          r.ReportId,
          r.RoomName,
          r.Status,
          r.CreatedAt,
          r.EndedAt,
          COUNT(DISTINCT rp.UserId) as TotalParticipants,
          COUNT(DISTINCT CASE WHEN rp.LeftAt IS NULL THEN rp.UserId END) as ActiveParticipants
        FROM Room r
        LEFT JOIN RoomParticipant rp ON r.RoomId = rp.RoomId
        GROUP BY r.RoomId, r.ReportId, r.RoomName, r.Status, r.CreatedAt, r.EndedAt
        ORDER BY r.CreatedAt DESC
      `);

    const stats = {
      totalRooms: result.recordset.length,
      activeRooms: result.recordset.filter(r => r.Status === 'active').length,
      rooms: result.recordset.map(room => ({
        roomId: room.RoomId,
        reportId: room.ReportId,
        roomName: room.RoomName,
        roomUrl: generateJitsiRoomUrl(room.RoomName, 'User'),
        status: room.Status,
        createdAt: room.CreatedAt,
        endedAt: room.EndedAt,
        totalParticipants: room.TotalParticipants,
        activeParticipants: room.ActiveParticipants
      }))
    };
    
    console.log('📊 Jitsi room stats requested:', stats);
    
    res.json({
      success: true,
      ...stats
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to get stats' 
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Debug endpoint to check specific report's Jitsi room - UPDATED with legitimate config
app.get('/api/jitsi/debug/:reportId', async (req, res) => {
  const { reportId } = req.params;
  let pool;

  try {
    pool = await sql.connect(config);
    const result = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query(`
        SELECT 
          r.RoomId,
          r.RoomName,
          r.Status,
          r.CreatedAt,
          r.EndedAt,
          r.CreatedBy,
          COUNT(rp.RoomParticipantId) as ParticipantCount
        FROM Room r
        LEFT JOIN RoomParticipant rp ON r.RoomId = rp.RoomId
        WHERE r.ReportId = @ReportId
        GROUP BY r.RoomId, r.RoomName, r.Status, r.CreatedAt, r.EndedAt, r.CreatedBy
      `);
  
    const rooms = result.recordset.map(room => ({
      roomId: room.RoomId,
      roomName: room.RoomName,
      roomUrl: generateJitsiRoomUrl(room.RoomName, 'User'),
      status: room.Status,
      createdAt: room.CreatedAt,
      endedAt: room.EndedAt,
      createdBy: room.CreatedBy,
      participantCount: room.ParticipantCount,
      configuration: 'legitimate'
    }));
  
    res.json({
      reportId: reportId,
      exists: result.recordset.length > 0,
      rooms: rooms
    });

  } catch (error) {
    console.error('Debug error:', error);
    res.status(500).json({
      success: false,
      message: 'Debug failed'
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});

// Test Jitsi room configuration - UPDATED with legitimate config
app.get('/api/jitsi/test-config', async (req, res) => {
  const { roomName = 'test-room', userName = 'Test User' } = req.query;
  
  try {
    const roomUrl = generateJitsiRoomUrl(roomName, userName, true);
    
    res.json({
      success: true,
      roomName: roomName,
      roomUrl: roomUrl,
      configuration: {
        prejoinPageEnabled: false,
        enableWelcomePage: false,
        requireDisplayName: false,
        startWithAudioMuted: false,
        startWithVideoMuted: false,
        method: 'legitimate'
      },
      testUrl: roomUrl
    });
    
  } catch (error) {
    console.error('Test config error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate test configuration'
    });
  }
});

// NEW ENDPOINT: Check if SOS report needs Jitsi room - UPDATED with legitimate config
app.get('/api/jitsi/check-sos-room', async (req, res) => {
  const { reportId } = req.query;
  let pool;

  try {
    pool = await sql.connect(config);
    
    // Check report type and room status
    const result = await pool.request()
      .input('ReportId', sql.Int, reportId)
      .query(`
        SELECT 
          r.emergencyType,
          r.Report_Status,
          rm.RoomId,
          rm.RoomName,
          rm.Status as RoomStatus
        FROM [dbo].[Report] r
        LEFT JOIN Room rm ON r.ReportID = rm.ReportId AND rm.Status = 'active'
        WHERE r.ReportID = @ReportId
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    const data = result.recordset[0];
    const isSOS = data.emergencyType === 'SOS';
    const hasRoom = data.RoomId !== null;
    
    let roomUrl = null;
    if (hasRoom) {
      roomUrl = generateJitsiRoomUrl(data.RoomName, 'User');
    }

    res.json({
      success: true,
      isSOSReport: isSOS,
      hasJitsiRoom: hasRoom,
      needsRoom: isSOS && !hasRoom,
      ...(hasRoom && {
        roomId: data.RoomId,
        roomName: data.RoomName,
        roomUrl: roomUrl,
        configuration: 'legitimate'
      })
    });

  } catch (error) {
    console.error('Check SOS room error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check SOS room status'
    });
  } finally {
    if (pool) {
      await pool.close();
    }
  }
});









app.post('/addTrustedContact', async (req, res) => {
  const { fName, phoneNum, emailAdd, isMem, userID } = req.body;
  console.log("Received Trusted contact info: ", req.body);

  if (!fName || !phoneNum || !isMem || !userID) {
    return res.status(400).json({
      message: 'Required fields are missing: Full name, Phone Number, isMember, or userID.'
    });
  }

  try {
    const pool = await sql.connect(config);

    const trustedResult = await pool.request()
      .input('fullName', sql.VarChar, fName)
      .input('phoneNumber', sql.VarChar, phoneNum)
      .input('emailAddress', sql.VarChar, emailAdd || null)
      .input('isMember', sql.VarChar, isMem)
      .input('userId', sql.BigInt, userID)
      .query(`
                INSERT INTO [dbo].[trustedContact]
                (fullName, phoneNumber, emailAddress, isMember, userId)
                OUTPUT INSERTED.trustedContactID
                VALUES
                (@fullName, @phoneNumber, @emailAddress, @isMember, @userId)
            `);

    console.log("Trusted contact added, ID:", trustedResult.recordset[0].trustedContactID);
    res.status(201).json({
      success: true,
      trustedContactID: trustedResult.recordset[0].trustedContactID
    });
  } catch (err) {
    console.error('Error submitting trusted contact:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

app.post('/addNotification', async (req, res) => {
  const { userIds, notiTitle, msg, readStatus, reportid, reporterID, notiType } = req.body;

  console.log('=== DEBUG: addNotification called ===');
  console.log('Request body:', req.body);

  if (!userIds || typeof userIds !== 'string') {
    return res.status(400).json({ success: false, message: 'Invalid userIds parameter.' });
  }

  const tokens = userIds.trim().split(' ').filter(token => token.length > 0);
  const validUserIds = tokens
    .map(token => parseInt(token))
    .filter(userId => !isNaN(userId) && userId !== parseInt(reporterID));

  console.log('Valid user IDs:', validUserIds);

  if (validUserIds.length === 0) {
    return res.status(400).json({ success: false, message: 'No valid user IDs provided.' });
  }

  try {
    const pool = await sql.connect(config);

    // Method 1: Use dynamic SQL with IN clause
    const userIdList = validUserIds.join(',');

    const result = await pool.request()
      .input('notiTitle', sql.VarChar, notiTitle)
      .input('msg', sql.VarChar, msg)
      .input('readStatus', sql.VarChar, readStatus)
      .input('reportID', sql.Int, reportid)
      .input('NotiType', sql.VarChar, notiType)
      .query(`
        WITH UserList AS (
          SELECT value AS userId
          FROM STRING_SPLIT('${userIdList}', ',')
          WHERE value != ''
        )
        INSERT INTO [dbo].[Notification]
        (notiTitle, msg, readStatus, createdDate, reportID, userId, NotiType)
        OUTPUT INSERTED.notificationID
        SELECT
          @notiTitle,
          @msg,
          @readStatus,
          dbo.GetSASTDateTime(),
          @reportID,
          CAST(ul.userId AS INT),
          @NotiType
        FROM UserList ul
        WHERE ISNUMERIC(ul.userId) = 1
      `);

    const insertedNotificationIDs = result.recordset.map(row => row.notificationID);
    console.log(`Notifications added for ${insertedNotificationIDs.length} users:`, insertedNotificationIDs);

    res.status(201).json({
      success: true,
      insertedNotificationIDs,
      totalInserted: insertedNotificationIDs.length
    });

  } catch (err) {
    console.error('Error submitting notification:', err);
    console.error('Error details:', {
      message: err.message,
      code: err.code,
      number: err.number
    });

    // Fallback: Try individual inserts if STRING_SPLIT fails
    if (err.message.includes('STRING_SPLIT')) {
      console.log('STRING_SPLIT not available, trying individual inserts...');
      try {
        const pool = await sql.connect(config);
        const insertedNotificationIDs = [];

        for (const userId of validUserIds) {
          const result = await pool.request()
            .input('notiTitle', sql.VarChar, notiTitle)
            .input('msg', sql.VarChar, msg)
            .input('readStatus', sql.VarChar, readStatus)
            .input('reportID', sql.Int, reportid)
            .input('userId', sql.Int, userId)
            .input('NotiType', sql.VarChar, notiType)
            .query(`
              INSERT INTO [dbo].[Notification]
              (notiTitle, msg, readStatus, createdDate, reportID, userId, NotiType)
              OUTPUT INSERTED.notificationID
              VALUES (
                @notiTitle,
                @msg,
                @readStatus,
                dbo.GetSASTDateTime(),
                @reportID,
                @userId,
                @NotiType
              )
            `);

          if (result.recordset && result.recordset.length > 0) {
            insertedNotificationIDs.push(result.recordset[0].notificationID);
          }
        }

        res.status(201).json({
          success: true,
          insertedNotificationIDs,
          totalInserted: insertedNotificationIDs.length
        });

      } catch (fallbackErr) {
        console.error('Fallback method also failed:', fallbackErr);
        res.status(500).json({
          success: false,
          message: 'Internal server error.',
          error: fallbackErr.message
        });
      }
    } else {
      res.status(500).json({
        success: false,
        message: 'Internal server error.',
        error: err.message
      });
    }
  }
});


app.get('/getTrustedContacts', async (req, res) => {
  const userId = parseInt(req.query.userId);

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ message: 'Missing or invalid userID.' });
  }
  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`SELECT * FROM [dbo].[trustedContact] WHERE userId = @userId`);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'Trusted contacts not found.' });
    }
    res.status(200).json({ success: true, TrustedContacts: result.recordset });
  }
  catch (err) {
    console.error('Error fetching trusted contacts:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

app.get('/getComMembers', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .query(`SELECT * FROM [dbo].[CommunityMember]`);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'Community members not found.' });
    }
    res.status(200).json({ success: true, CommunityMember: result.recordset });
  }
  catch (err) {
    console.error('Error fetching community members:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


app.delete('/deleteTrustedContact', async (req, res) => {
  const { id } = req.query;

  if (!id) {
    return res.status(400).json({
      message: 'Trusted contact ID is required.'
    });
  }

  try {
    const pool = await sql.connect(config);

    const deleteResult = await pool.request()
      .input('trustedContactID', sql.BigInt, id)
      .query(`
                DELETE FROM [dbo].[trustedContact]
                WHERE trustedContactID = @trustedContactID
            `);

    if (deleteResult.rowsAffected[0] === 0) {
      return res.status(404).json({
        success: false,
        message: 'Trusted contact not found.'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Trusted contact deleted successfully.'
    });
  } catch (err) {
    console.error('Error deleting trusted contact:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

app.get('/user', async (req, res) => {
  const userID = parseInt(req.query.userID);

  try {
    const pool = await sql.connect(config);

    if (!userID || isNaN(userID)) {
      // No userID provided or invalid → return all users
      const result = await pool.request()
        .query(`SELECT * FROM [dbo].[Users]`);
      return res.status(200).json({ success: true, Users: result.recordset });
    }

    // userID provided and valid → return specific user
    const result = await pool.request()
      .input('UserID', sql.Int, userID)
      .query(`SELECT * FROM [dbo].[Users] WHERE UserID = @UserID`);

    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }
    return res.status(200).json({ success: true, User: result.recordset[0] });
  }
  catch (err) {
    console.error('Error fetching user(s):', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});
app.get('/getFullName', async (req, res) => {
  const userID = parseInt(req.query.userID);

  if (!userID || isNaN(userID)) {
    return res.status(400).json({ success: false, message: 'Invalid or missing userID.' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userID)
      .query(`SELECT FullName FROM [dbo].[Users] WHERE UserID = @UserID`);

    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.status(200).json({
      success: true,
      FullName: result.recordset[0].FullName
    });

  } catch (err) {
    console.error('Error fetching full name:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});
app.get('/getUsername', async (req, res) => {
  const userID = parseInt(req.query.userID);

  if (!userID || isNaN(userID)) {
    return res.status(400).json({ success: false, message: 'Invalid or missing userID.' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userID)
      .query(`SELECT Username FROM [dbo].[Users] WHERE UserID = @UserID`);

    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.status(200).json({
      success: true,
      Username: result.recordset[0].Username
    });

  } catch (err) {
    console.error('Error fetching username:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


app.get('/comMember', async (req, res) => {
  const userID = parseInt(req.query.userID);

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('UserID', sql.BigInt, userID)
      .query(`SELECT * FROM [dbo].[CommunityMember] WHERE UserID=@UserID`);
    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: 'CommunityMember not found.' });
    }
    return res.status(200).json({ success: true, CommunityMember: result.recordset[0] });
  }
  catch (err) {
    console.error('Error fetching community member:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

app.get('/report', async (req, res) => {
  const reportId = parseInt(req.query.reportId);

  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Missing or invalid reportId.' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('ReportID', sql.Int, reportId)
      .query('SELECT * FROM [dbo].[Report] WHERE ReportID = @ReportID');

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'Report not found.' });
    }

    res.status(200).json({ success: true, report: result.recordset[0] });
  } catch (err) {
    console.error('Error fetching report:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});
app.get('/reportNoMedia', async (req, res) => {
  const reportId = parseInt(req.query.reportId);

  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Missing or invalid reportId.' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('ReportID', sql.Int, reportId)
      .query(`
        SELECT ReportID, ReporterID, emergencyType, emerDescription, sharedWith,
               Report_Location, Report_Status, dateReported, suburbName
        FROM [dbo].[Report]
        WHERE ReportID = @ReportID
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'Report not found.' });
    }

    res.status(200).json({ success: true, report: result.recordset[0] });
  } catch (err) {
    console.error('Error fetching report (no media):', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


//get report
app.get('/getReportWithReporter', async (req, res) => {
  const { id } = req.query;

  if (!id) {
    return res.status(400).json({
      success: false,
      message: 'Report ID is required',
    });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('ReportID', sql.Int, id)
      .query(`
        SELECT 
          r.ReportID,
          r.emergencyType,
          r.emerDescription,
          r.media_Photo,
          r.media_Voice,
          r.sharedWith,
          r.Report_Location,
          r.Report_Status,
          r.ReporterID,
          r.dateReported,

          u.FullName,
          u.Email,
          u.Username,
          u.PhoneNumber,
          u.UserType,
          u.ProfilePhoto
        FROM Report r
        INNER JOIN Users u ON r.ReporterID = u.UserID
        WHERE r.ReportID = @ReportID
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No report found for the given ID',
      });
    }

    const row = result.recordset[0];

    const response = {
      Report: {
        ReportID: row.ReportID,
        EmergencyType: row.emergencyType,
        EmerDescription: row.emerDescription,
        MediaPhoto: row.media_Photo,
        MediaVoice: row.media_Voice,
        SharedWith: row.sharedWith,
        Report_Location: row.Report_Location,
        Report_Status: row.Report_Status,
        ReporterID: row.ReporterID,
        dateReported : row.dateReported,
      },
      Reporter: {
        FullName: row.FullName,
        Email: row.Email,
        Username: row.Username,
        PhoneNumber: row.PhoneNumber,
        UserType: row.UserType,
        ProfilePhoto: row.ProfilePhoto,
      }
    };

    res.status(200).json({
      success: true,
      data: response,
    });

  } catch (error) {
    console.error("Error fetching report and reporter:", error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});


app.get('/getNotification', async (req, res) => {
  const userId = parseInt(req.query.userId);

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ message: 'Missing or invalid userId.' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('userId', sql.BigInt, userId)
      .query(`SELECT * FROM [dbo].[Notification] WHERE userId = @userId AND readStatus='unread'`);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'No notifications found.' });
    }

    res.status(200).json({ success: true, notifications: result.recordset });
  } catch (err) {
    console.error('Error fetching notifications:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});
app.get('/getReporter', async (req, res) => {
  const reportId = parseInt(req.query.reportId);
  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Missing or invalid reportId.' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('reportId', sql.BigInt, reportId)
      .query(`
            SELECT u.*
            FROM [dbo].[Report] r
            JOIN Users u ON r.ReporterID = u.UserID
            WHERE r.ReportID=@reportId
            `);
    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'No user found for given reportId' });
    }
    res.json({ User: result.recordset[0] });
  }
  catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

app.post('/acceptReport', async (req, res) => {
  const { UserID, res_Location, res_Status, reportID } = req.body;
  console.log('Received data: ', req.body);

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, UserID)
      .input('res_Location', sql.VarChar(sql.MAX), res_Location)
      .input('res_Status', sql.VarChar(sql.MAX), res_Status)
      .input('reportID', sql.Int, reportID)
      .query(`
        INSERT INTO Response (UserID, res_Location, res_Status, reportID, dateAccepted)
        OUTPUT INSERTED.ResponseID
        VALUES (@UserID, @res_Location, @res_Status, @reportID, dbo.GetSASTDateTime())
      `);

    const insertedID = result.recordset[0].ResponseID;
    res.status(201).json({ ResponseID: insertedID });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database insertion failed' });
  }
});

app.get('/responders', async (req, res) => {
  const reportId = parseInt(req.query.reportId);

  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Missing or invalid reportId.' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('reportID', sql.BigInt, reportId)
      .query(`
                SELECT * FROM [dbo].[Response]
                WHERE reportID = @reportID 
                AND res_Status NOT IN ('Completed', 'Cancelled')
            `);

    res.json({ success: true, Response: result.recordset });
  } catch (err) {
    console.error('Error fetching Responses:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});
// New endpoint specifically for fetching user profile with photo
app.get('/api/user/profile', async (req, res) => {
  const userID = parseInt(req.query.userID);

  if (!userID || isNaN(userID)) {
    return res.status(400).json({ success: false, message: 'Missing or invalid userID.' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('UserID', sql.Int, userID)
      .query(`SELECT UserID, FullName, ProfilePhoto FROM [dbo].[Users] WHERE UserID = @UserID`);

    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.status(200).json({ success: true, User: result.recordset[0] });
  }
  catch (err) {
    console.error('Error fetching user profile:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// New batch endpoint to fetch multiple user profiles at once
app.post('/api/users/profiles/batch', async (req, res) => {
  const { userIds } = req.body;

  if (!Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).json({ success: false, message: 'Missing or invalid userIds array.' });
  }

  // Validate all userIds are numbers and limit batch size for performance
  const validUserIds = userIds.filter(id => typeof id === 'number' && !isNaN(id)).slice(0, 50);
  if (validUserIds.length === 0) {
    return res.status(400).json({ success: false, message: 'No valid userIds provided.' });
  }

  try {
    const pool = await sql.connect(config);

    // Create parameterized query for multiple IDs
    const placeholders = validUserIds.map((_, index) => `@UserID${index}`).join(',');
    const request = pool.request();

    // Add parameters for each user ID
    validUserIds.forEach((id, index) => {
      request.input(`UserID${index}`, sql.Int, id);
    });

    const result = await request.query(`
      SELECT UserID, FullName, ProfilePhoto 
      FROM [dbo].[Users] 
      WHERE UserID IN (${placeholders})
    `);

    return res.status(200).json({
      success: true,
      Users: result.recordset
    });
  }
  catch (err) {
    console.error('Error fetching user profiles batch:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// New endpoint for responders with basic user info in single query
app.get('/api/responders/with-profiles', async (req, res) => {
  const reportId = parseInt(req.query.reportId);
  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Missing or invalid reportId.' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('reportID', sql.BigInt, reportId)
      .query(`
        SELECT 
          r.ResponseID,
          r.UserID,
          r.reportID,
          r.res_Location,
          r.res_Status,
          u.FullName,
          u.ProfilePhoto
        FROM [dbo].[Response] r
        LEFT JOIN [dbo].[Users] u ON r.UserID = u.UserID
        WHERE r.reportID = @reportID
        AND r.res_Status NOT IN ('Completed', 'Cancelled')
      `);
    res.json({ success: true, Response: result.recordset });
  } catch (err) {
    console.error('Error fetching responders with profiles:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// New endpoint for minimal responder data (for frequent polling)
app.get('/api/responders/minimal', async (req, res) => {
  const reportId = parseInt(req.query.reportId);
  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Missing or invalid reportId.' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('reportID', sql.BigInt, reportId)
      .query(`
        SELECT ResponseID, UserID, res_Status, res_Location
        FROM [dbo].[Response]
        WHERE reportID = @reportID
        AND res_Status NOT IN ('Completed', 'Cancelled')
      `);
    res.json({ success: true, Response: result.recordset });
  } catch (err) {
    console.error('Error fetching minimal responders:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// New endpoint to check for new responders (returns only UserIDs)
app.get('/api/responders/check-new', async (req, res) => {
  const reportId = parseInt(req.query.reportId);
  const knownUserIds = req.query.knownUserIds ? req.query.knownUserIds.split(',').map(id => parseInt(id)).filter(id => !isNaN(id)) : [];

  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Missing or invalid reportId.' });
  }

  try {
    const pool = await sql.connect(config);
    let query = `
      SELECT DISTINCT UserID
      FROM [dbo].[Response]
      WHERE reportID = @reportID
      AND res_Status NOT IN ('Completed', 'Cancelled')
    `;

    const request = pool.request().input('reportID', sql.BigInt, reportId);

    // If we have known user IDs, exclude them
    if (knownUserIds.length > 0) {
      const placeholders = knownUserIds.map((_, index) => `@KnownUserID${index}`).join(',');
      knownUserIds.forEach((id, index) => {
        request.input(`KnownUserID${index}`, sql.Int, id);
      });
      query += ` AND UserID NOT IN (${placeholders})`;
    }

    const result = await request.query(query);
    const newUserIds = result.recordset.map(row => row.UserID);

    res.json({ success: true, newUserIds });
  } catch (err) {
    console.error('Error checking for new responders:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// New endpoint for user basic info only (no profile photo)
app.get('/api/user/basic', async (req, res) => {
  const userID = parseInt(req.query.userID);

  if (!userID || isNaN(userID)) {
    return res.status(400).json({ success: false, message: 'Missing or invalid userID.' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('UserID', sql.Int, userID)
      .query(`SELECT UserID, FullName, Email, Username, UserType FROM [dbo].[Users] WHERE UserID = @UserID`);

    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.status(200).json({ success: true, User: result.recordset[0] });
  }
  catch (err) {
    console.error('Error fetching basic user info:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});


app.post('/addMessage', async (req, res) => {
  const { ReporterId, ResponderId, ReportId, msg } = req.body;
  if (!ReporterId || !ResponderId || !ReportId || !msg) {
    return res.status(400).json({ error: 'reporterID, responderID, reportID and msg are required' });
  }
  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('reporterID', sql.Int, ReporterId)
      .input('responderID', sql.Int, ResponderId)
      .input('reportID', sql.Int, ReportId)
      .input('msg', sql.VarChar(sql.MAX), msg) // use max length for msg
      .query(`
                INSERT INTO [dbo].[chatMessage] 
                (reporterID, responderID, reportID, timeSent, msg)
                OUTPUT INSERTED.msgID
                VALUES (@reporterID, @responderID, @reportID, dbo.GetSASTDateTime(), @msg)
            `);

    res.status(201).json({ msgID: result.recordset[0].msgID });
  }
  catch (err) {
    console.error('SQL error', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/getMessages', async (req, res) => {
  const { reportID } = req.query;  // get from query string

  if (!reportID) {
    return res.status(400).json({ error: 'reportID is required' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('reportID', sql.Int, parseInt(reportID, 10))
      .query(`
                SELECT * FROM [dbo].[chatMessage]
                WHERE reportID = @reportID
                ORDER BY timeSent ASC
            `);

    res.status(200).json(result.recordset);
  }
  catch (err) {
    console.error('SQL error', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/notifications/mark-read', async (req, res) => {
  const { reportID, userId } = req.body;
  console.log(req.body);

  if (!reportID || !userId) {
    return res.status(400).json({ success: false, message: 'Missing reportID or userId' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('reportID', sql.Int, reportID)
      .input('userId', sql.Int, userId)
      .query(`
        UPDATE Notification
        SET readStatus = 'read'
        WHERE reportID = @reportID AND userId = @userId
      `);

    res.status(200).json({
      success: true,
      message: 'Notification marked as read',
      rowsAffected: result.rowsAffected[0]
    });
  } catch (err) {
    console.error('Error updating notification status:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


//******************BROADCAST MESSAGING ENDPOINTS********************//

app.get('/api/current-user', requireAuth, (req, res) => {
  console.log('Session data:', req.session);
  res.json({
    success: true,
    user: req.session.user
  });
});

app.post('/api/messages', requireAuth, async (req, res) => {
  const { content, image64 } = req.body;
  const channelId = 1; // Melville Emergency Channel
  const senderId = req.session.user.id;

  try {
    const pool = await sql.connect(config);

    // First insert the message (initially not flagged)
    const result = await pool.request()
      .input('ChannelID', sql.Int, channelId)
      .input('SenderID', sql.Int, senderId)
      .input('Content', sql.NVarChar(sql.MAX), content)
      .input('Image64', sql.NVarChar(sql.MAX), image64 || null)
      .query(`
        INSERT INTO Messages (ChannelID, SenderID, Content, images64, Flagged)
        OUTPUT INSERTED.MessageID, INSERTED.SentAt
        VALUES (@ChannelID, @SenderID, @Content, @Image64, NULL)
      `);

    // Get sender info
    const senderInfo = await pool.request()
      .input('UserID', sql.Int, senderId)
      .query('SELECT FullName FROM Users WHERE UserID = @UserID');

    // Respond immediately to client
    res.status(201).json({
      success: true,
      message: {
        id: result.recordset[0].MessageID,
        senderId,
        senderName: senderInfo.recordset[0]?.FullName || 'Unknown',
        content,
        image64,
        sentAt: result.recordset[0].SentAt,
        isCurrentUser: true,
        flagged: null // Initially not flagged
      }
    });

    // Perform content analysis in background - DON'T BLOCK THE RESPONSE
    // Use setImmediate to ensure this runs after the response is sent
    setImmediate(async () => {

      try {
        console.log(`Starting background analysis for message ${result.recordset[0].MessageID}`);

        const { shouldFlag, reasons, totalScore } = await checkMessageForAds(content, image64);

        console.log(`Analysis complete for message ${result.recordset[0].MessageID}: shouldFlag=${shouldFlag}, score=${totalScore}`);

        if (shouldFlag) {
          // Create new pool connection for background operation
          const backgroundPool = await sql.connect(config);

          await backgroundPool.request()
            .input('MessageID', sql.Int, result.recordset[0].MessageID)
            .input('Flagged', sql.VarChar(sql.MAX), reasons)
            .query('UPDATE Messages SET Flagged = @Flagged WHERE MessageID = @MessageID');

          await backgroundPool.request()
            .input('MessageID', sql.Int, result.recordset[0].MessageID)
            .input('UserID', sql.Int, senderId)
            .input('Reason', sql.VarChar(255), reasons.substring(0, 255)) // Ensure it fits in VARCHAR(255)
            .query(`
              INSERT INTO FlaggedMessages (MessageID, UserID, Reason)
              VALUES (@MessageID, @UserID, @Reason)
            `);

          // Create notification for admins
          try {
            // Get all Leaders
            const admins = await backgroundPool.request()
              .query("SELECT UserID FROM CommunityMember WHERE Role = 'CommunityLeader'");

            if (admins.recordset.length > 0) {
              // Create notification
              const notifResult = await backgroundPool.request()
                .input('NotificationType', sql.VarChar(50), 'MESSAGE_FLAGGED')
                .input('EntityType', sql.VarChar(50), 'MESSAGE')
                .input('EntityID', sql.Int, result.recordset[0].MessageID)
                .input('Title', sql.VarChar(255), 'Message Flagged')
                .input('Message', sql.VarChar(sql.MAX), `Message flagged: ${reasons.substring(0, 200)}`)
                .query(`
                  INSERT INTO Notifications 
                  (NotificationType, EntityType, EntityID, Title, Message)
                  OUTPUT INSERTED.NotificationID
                  VALUES (@NotificationType, @EntityType, @EntityID, @Title, @Message)
                `);

              const notificationId = notifResult.recordset[0].NotificationID;

              // Add recipients
              const values = admins.recordset.map(admin =>
                `(${notificationId}, ${admin.UserID})`
              ).join(',');

              await backgroundPool.request().query(`
                INSERT INTO NotificationRecipients (NotificationID, UserID)
                VALUES ${values}
              `);
            }
          } catch (notifErr) {
            console.error('Failed to create flag notification:', notifErr);
          }

          console.log(`Message ${result.recordset[0].MessageID} flagged (score: ${totalScore}): ${reasons}`);

          // Close the background pool connection
          await backgroundPool.close();
        } else {
          console.log(`Message ${result.recordset[0].MessageID} passed content check (score: ${totalScore})`);
        }
      } catch (err) {
        console.error(`Error in background content check for message ${result.recordset[0].MessageID}:`, err);
      }
    });

  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});


// GET /api/messages
app.get('/api/messages', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const channelId = 1; // Melville Emergency Channel

  try {
    const pool = await sql.connect(config);

    // First get all messages
    const result = await pool.request()
      .input('ChannelID', sql.Int, channelId)
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT 
            m.MessageID as id,
            m.SenderID as senderId,
            u.FullName as senderName,
            m.Content as text,
            m.images64 as image64,
            m.SentAt as time,
            CASE WHEN m.SenderID = @UserID THEN 1 ELSE 0 END as isCurrentUser,
            CASE WHEN r.MessageID IS NOT NULL THEN 1 ELSE 0 END as isRead
        FROM Messages m
        JOIN Users u ON m.SenderID = u.UserID
        LEFT JOIN MessageReadStatus r ON m.MessageID = r.MessageID AND r.UserID = @UserID
        WHERE m.ChannelID = @ChannelID 
        AND m.isActive = 'Yes'
        ORDER BY m.SentAt ASC
      `);

    // Identify unread messages not sent by current user
    const unreadMessages = result.recordset.filter(msg =>
      !msg.isRead && !msg.isCurrentUser
    );

    // Mark them as read
    if (unreadMessages.length > 0) {
      await Promise.all(
        unreadMessages.map(msg =>
          pool.request()
            .input('MessageID', sql.Int, msg.id)
            .input('UserID', sql.Int, userId)
            .query(`
              IF NOT EXISTS (
                SELECT 1 FROM MessageReadStatus 
                WHERE MessageID = @MessageID AND UserID = @UserID
              )
              BEGIN
                INSERT INTO MessageReadStatus (MessageID, UserID, ReadAt)
                VALUES (@MessageID, @UserID, dbo.GetSASTDateTime())
              END
            `)
        )
      );

      // Update the isRead status in the response
      result.recordset.forEach(msg => {
        if (unreadMessages.some(m => m.id === msg.id)) {
          msg.isRead = true;
        }
      });
    }

    res.status(200).json({
      success: true,
      messages: result.recordset
    });

  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
});

// Mark message as read
app.post('/api/messages/read', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const { messageId } = req.body;

  try {
    const pool = await sql.connect(config);

    // First check if the message exists
    const messageExists = await pool.request()
      .input('MessageID', sql.Int, messageId)
      .query('SELECT 1 FROM Messages WHERE MessageID = @MessageID');

    if (messageExists.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Check if already marked as read to avoid duplicates
    const alreadyRead = await pool.request()
      .input('MessageID', sql.Int, messageId)
      .input('UserID', sql.Int, userId)
      .query('SELECT 1 FROM MessageReadStatus WHERE MessageID = @MessageID AND UserID = @UserID');

    if (alreadyRead.recordset.length > 0) {
      return res.status(200).json({
        success: true,
        message: 'Message was already marked as read'
      });
    }

    // Insert with SAST timestamp
    await pool.request()
      .input('MessageID', sql.Int, messageId)
      .input('UserID', sql.Int, userId)
      .query(`
                INSERT INTO MessageReadStatus (MessageID, UserID, ReadAt)
                VALUES (@MessageID, @UserID, dbo.GetSASTDateTime())
            `);

    // Get the SAST timestamp for the response
    const sastTimeResult = await pool.request()
      .query('SELECT dbo.GetSASTDateTime() AS sastTime');
    const readAt = sastTimeResult.recordset[0].sastTime;

    res.status(200).json({
      success: true,
      readAt: readAt.toISOString()
    });

  } catch (err) {
    console.error('Error marking message as read:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to mark message as read',
      error: err.message
    });
  }
});

// GET /api/messages/unread-count
app.get('/api/messages/unread-count', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const channelId = 1; // Melville Emergency Channel

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .input('ChannelID', sql.Int, channelId)
      .query(`
                SELECT COUNT(*) as count
                FROM Messages m
                LEFT JOIN MessageReadStatus r ON m.MessageID = r.MessageID AND r.UserID = @UserID
                WHERE m.ChannelID = @ChannelID
                AND m.SenderID != @UserID  -- Only count messages from others
                AND r.MessageID IS NULL    -- Only count unread messages
                AND m.isActive = 'Yes'
            `);

    res.status(200).json({
      success: true,
      count: result.recordset[0].count
    });

  } catch (err) {
    console.error('Error counting unread messages:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to count unread messages',
      error: err.message
    });
  }
});

// POST /api/notifications
app.post('/api/notifications', async (req, res) => {
  const { content } = req.body;
  const channelId = 1; // Melville Emergency Channel
  const systemUserId = 0; // System user

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('ChannelID', sql.Int, channelId)
      .input('SenderID', sql.Int, systemUserId)
      .input('Content', sql.NVarChar(sql.MAX), content)
      .query(`
                INSERT INTO Messages (ChannelID, SenderID, Content)
                OUTPUT INSERTED.MessageID, INSERTED.SentAt
                VALUES (@ChannelID, @SenderID, @Content)
            `);

    res.status(201).json({
      success: true,
      notification: {
        id: result.recordset[0].MessageID,
        content,
        sentAt: result.recordset[0].SentAt,
        isSystem: true
      }
    });

  } catch (err) {
    console.error('Error broadcasting notification:', err);
    res.status(500).json({ success: false, message: 'Failed to broadcast notification' });
  }
});



app.get('/api/messages/latest', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const lastMessageId = req.query.lastMessageId || 0;
  const channelId = 1; // Melville Emergency Channel

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .input('LastMessageID', sql.Int, lastMessageId)
      .input('ChannelID', sql.Int, channelId)
      .query(`
        SELECT 
            m.MessageID as id,
            m.SenderID as senderId,
            u.FullName as senderName,
            m.Content as text,
            m.images64 as image64,
            m.SentAt as time,
            CASE WHEN m.SenderID = @UserID THEN 1 ELSE 0 END as isCurrentUser,
            CASE WHEN r.MessageID IS NOT NULL THEN 1 ELSE 0 END as isRead
        FROM Messages m
        JOIN Users u ON m.SenderID = u.UserID
        LEFT JOIN MessageReadStatus r ON m.MessageID = r.MessageID AND r.UserID = @UserID
        WHERE m.MessageID > @LastMessageID AND m.ChannelID = @ChannelID AND m.isActive = 'Yes'
        ORDER BY m.SentAt ASC
      `);

    // Mark unread messages as read
    const unreadMessages = result.recordset.filter(msg =>
      !msg.isRead && !msg.isCurrentUser
    );

    if (unreadMessages.length > 0) {
      await Promise.all(
        unreadMessages.map(msg =>
          pool.request()
            .input('MessageID', sql.Int, msg.id)
            .input('UserID', sql.Int, userId)
            .query(`
              IF NOT EXISTS (
                SELECT 1 FROM MessageReadStatus 
                WHERE MessageID = @MessageID AND UserID = @UserID
              )
              BEGIN
                INSERT INTO MessageReadStatus (MessageID, UserID, ReadAt)
                VALUES (@MessageID, @UserID, dbo.GetSASTDateTime())
              END
            `)
        )
      );

      // Update the isRead status in the response
      result.recordset.forEach(msg => {
        if (unreadMessages.some(m => m.id === msg.id)) {
          msg.isRead = true;
        }
      });
    }

    res.status(200).json({
      success: true,
      messages: result.recordset
    });

  } catch (err) {
    console.error('Error fetching latest messages:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
});


app.get('/api/messages/flagged', requireAuth, async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .query(`
        SELECT 
          m.MessageID, m.Content, m.images64, m.SentAt, m.Flagged,
          u.FullName as SenderName,
          f.FlagID, f.Reason
        FROM Messages m
        JOIN FlaggedMessages f ON m.MessageID = f.MessageID
        JOIN Users u ON m.SenderID = u.UserID
        WHERE m.Flagged IS NOT NULL
        ORDER BY m.SentAt DESC
      `);

    res.status(200).json({
      success: true,
      flaggedMessages: result.recordset
    });

  } catch (err) {
    console.error('Error fetching flagged messages:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch flagged messages' });
  }
});

app.get('/currentReports', async (req, res) => {
  const { userId } = req.query;

  try {
    const pool = await sql.connect(config);

    const request = pool.request();
    request.input('userId', sql.Int, userId);

    const result = await request.query(`
      SELECT r.* 
      FROM Response resp
      JOIN Report r ON r.ReportID = resp.reportID
      WHERE resp.UserID = @userId AND r.Report_Status='On-going' AND resp.res_Status='en-route'
    `);

    res.json({ reports: result.recordset });
  } catch (err) {
    console.error('Error fetching reports:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});





// Basic Test Endpoint
app.get('/', (req, res) => {
  res.json("Hi, I am the backend.");
});

// Start Server
app.listen(3000, () => {
  console.log("Server started ");
});

// Test Admin and CommunityMember Registration
async function testRegistration(payload, label) {
  console.log(`\n--- Testing ${label} Registration ---`);
  try {
    const res = await fetch('http://localhost:3000/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const textData = await res.text();
    console.log("Raw response:", textData);

    try {
      const data = JSON.parse(textData);
      console.log("Parsed data:", data);
    } catch (jsonErr) {
      console.error("Error parsing JSON:", jsonErr);
    }

    if (res.ok) {
      console.log("Registration successful.");
    } else {
      console.error("Registration failed.");
    }
  } catch (err) {
    console.error("Error testing the API:", err);
  }
}




//***************************TRUSTED USERS FUNCTIONALITY****************************************************** */

// Updated /api/trust-requests/send endpoint
app.post('/api/trust-requests/send', requireAuth, async (req, res) => {
  const { username, message } = req.body;
  const requesterId = req.session.user.id;
  console.log('sending user data found: ', { username, message, requesterId });

  if (!username) {
    return res.status(400).json({
      success: false,
      message: 'Username is required'
    });
  }

  try {
    const pool = await sql.connect(config);

    // First find the user by username to get their ID
    const userResult = await pool.request()
      .input('Username', sql.NVarChar(50), username)
      .query('SELECT UserID, FullName FROM Users WHERE Username = @Username');

    if (userResult.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const requestedUserId = userResult.recordset[0].UserID;
    const requestedUserName = userResult.recordset[0].FullName;

    // Check if request already exists
    const existingRequest = await pool.request()
      .input('RequesterID', sql.Int, requesterId)
      .input('RequestedID', sql.Int, requestedUserId)
      .query(`
        SELECT RequestID, Status FROM TrustRequests 
        WHERE RequesterID = @RequesterID AND RequestedID = @RequestedID
      `);

    if (existingRequest.recordset.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Trust request already exists',
        requestId: existingRequest.recordset[0].RequestID
      });
    }

    // Create new request
    const result = await pool.request()
      .input('RequesterID', sql.Int, requesterId)
      .input('RequestedID', sql.Int, requestedUserId)
      .input('Message', sql.NVarChar(255), message || null)
      .query(`
        INSERT INTO TrustRequests (RequesterID, RequestedID, Message, Status)
        OUTPUT INSERTED.RequestID
        VALUES (@RequesterID, @RequestedID, @Message, 'pending')
      `);

    // Get requester info for notification
    const requesterInfo = await pool.request()
      .input('UserID', sql.Int, requesterId)
      .query('SELECT FullName, Username FROM Users WHERE UserID = @UserID');

    res.status(201).json({
      success: true,
      requestId: result.recordset[0].RequestID,
      requesterName: requesterInfo.recordset[0]?.FullName || requesterInfo.recordset[0]?.Username || 'Unknown',
      requesterUsername: requesterInfo.recordset[0]?.Username
    });

  } catch (err) {
    console.error('Error sending trust request:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to send trust request',
      error: err.message
    });
  }
});

app.get('/api/trust-requests/pending', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  console.log(`Fetching pending requests for user ${userId}`);

  try {
    const pool = await sql.connect(config);

    // Verify user exists first
    const userExists = await pool.request()
      .input('UserID', sql.Int, userId)
      .query('SELECT 1 FROM Users WHERE UserID = @UserID');

    if (userExists.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Mark requests as viewed (but don't wait for completion)
    pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        UPDATE TrustRequests 
        SET Viewed = 1 
        WHERE RequestedID = @UserID AND Status = 'pending'
      `)
      .catch(err => console.error('Error marking as viewed:', err));

    // Fetch pending requests with requester info
    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT 
          tr.RequestID as requestId,
          tr.RequesterID as requesterId,
          u.FullName as requesterName,
          u.Username as requesterUsername,
          tr.Message as message,
          tr.RequestedAt as requestedAt,
          tr.Viewed as viewed
        FROM TrustRequests tr
        JOIN Users u ON tr.RequesterID = u.UserID
        WHERE tr.RequestedID = @UserID 
          AND tr.Status = 'pending'
        ORDER BY tr.RequestedAt DESC
      `);

    res.status(200).json({
      success: true,
      requests: result.recordset
    });

  } catch (err) {
    // Get SAST timestamp for error logging
    const sastTime = await sql.connect(config)
      .then(pool => pool.request().query('SELECT dbo.GetSASTDateTime() as sastTime'))
      .then(result => result.recordset[0].sastTime)
      .catch(() => new Date()); // Fallback to regular date if SAST time fails

    console.error('Error in pending requests:', {
      error: err.message,
      userId: userId,
      time: sastTime.toISOString()
    });

    res.status(500).json({
      success: false,
      message: 'Failed to fetch requests',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.post('/api/trust-requests/respond', requireAuth, async (req, res) => {
  const { requestId, accept } = req.body;
  const userId = req.session.user.id;
  console.log('Received trust requests response data:', {
    requestId,
    accept,
    userId
  });

  try {
    const pool = await sql.connect(config);

    // Verify the request exists and is pending
    const request = await pool.request()
      .input('RequestID', sql.Int, requestId)
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT RequesterID FROM TrustRequests 
        WHERE RequestID = @RequestID 
          AND RequestedID = @UserID 
          AND Status = 'pending'
      `);

    if (request.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Request not found or already responded'
      });
    }

    const requesterId = request.recordset[0].RequesterID;
    const newStatus = accept ? 'approved' : 'declined';

    // Update request status
    await pool.request()
      .input('RequestID', sql.Int, requestId)
      .input('Status', sql.VarChar(20), newStatus)
      .query(`
        UPDATE TrustRequests 
        SET Status = @Status, RespondedAt = dbo.GetSASTDateTime()
        WHERE RequestID = @RequestID
      `);

    if (accept) {
      // Create trusted relationship if accepted
      await pool.request()
        .input('TrustingUserID', sql.Int, requesterId)
        .input('TrustedUserID', sql.Int, userId)
        .input('RequestID', sql.Int, requestId)
        .query(`
          INSERT INTO TrustedContact 
          (TrustingUserID, TrustedUserID, RequestID)
          VALUES (@TrustingUserID, @TrustedUserID, @RequestID)
        `);
    }

    res.status(200).json({ success: true });

  } catch (err) {
    console.error('Error responding to trust request:', err);
    res.status(500).json({ success: false, message: 'Failed to respond to request' });
  }
});

app.get('/api/users/find', requireAuth, async (req, res) => {
  const { username } = req.query;
  console.log('Received user data found: ', req.body);

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('Username', sql.NVarChar(50), username)
      .query('SELECT UserID, FullName FROM Users WHERE Username = @Username');

    if (result.recordset.length > 0) {
      res.json({
        success: true,
        user: result.recordset[0]
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
  } catch (err) {
    console.error('Error finding user:', err);
    res.status(500).json({
      success: false,
      message: 'Error searching for user'
    });
  }
});

app.get('/api/trusted-contacts', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  console.log('getting trusted contacts for user:', userId);

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT 
          u.UserID as id,
          u.FullName as fullName,
          u.Email as email,
          u.PhoneNumber as phoneNumber,
          tr.RequestedAt as establishedAt
        FROM TrustedContact tc
        JOIN Users u ON tc.TrustedUserID = u.UserID
        LEFT JOIN TrustRequests tr ON tc.RequestID = tr.RequestID
        WHERE tc.TrustingUserID = @UserID
        ORDER BY tr.RequestedAt DESC
      `);

    res.status(200).json({
      success: true,
      contacts: result.recordset
    });

  } catch (err) {
    console.error('Error fetching trusted contacts:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch contacts',
      error: err.message
    });
  }
}); app.post('/api/trust-requests/send', requireAuth, async (req, res) => {
  const { username, message } = req.body;
  const requesterId = req.session.user.id;
  console.log('sending user data found: ', { username, message, requesterId });

  if (!username) {
    return res.status(400).json({
      success: false,
      message: 'Username is required'
    });
  }

  try {
    const pool = await sql.connect(config);

    // First find the user by username to get their ID
    const userResult = await pool.request()
      .input('Username', sql.NVarChar(50), username)
      .query('SELECT UserID, FullName FROM Users WHERE Username = @Username');

    if (userResult.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const requestedUserId = userResult.recordset[0].UserID;
    const requestedUserName = userResult.recordset[0].FullName;

    // Check if request already exists
    const existingRequest = await pool.request()
      .input('RequesterID', sql.Int, requesterId)
      .input('RequestedID', sql.Int, requestedUserId)
      .query(`
        SELECT RequestID, Status FROM TrustRequests 
        WHERE RequesterID = @RequesterID AND RequestedID = @RequestedID
      `);

    if (existingRequest.recordset.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Trust request already exists',
        requestId: existingRequest.recordset[0].RequestID
      });
    }

    // Create new request
    const result = await pool.request()
      .input('RequesterID', sql.Int, requesterId)
      .input('RequestedID', sql.Int, requestedUserId)
      .input('Message', sql.NVarChar(255), message || null)
      .query(`
        INSERT INTO TrustRequests (RequesterID, RequestedID, Message, Status)
        OUTPUT INSERTED.RequestID
        VALUES (@RequesterID, @RequestedID, @Message, 'pending')
      `);

    // Get requester info for notification
    const requesterInfo = await pool.request()
      .input('UserID', sql.Int, requesterId)
      .query('SELECT FullName, Username FROM Users WHERE UserID = @UserID');

    res.status(201).json({
      success: true,
      requestId: result.recordset[0].RequestID,
      requesterName: requesterInfo.recordset[0]?.FullName || requesterInfo.recordset[0]?.Username || 'Unknown',
      requesterUsername: requesterInfo.recordset[0]?.Username
    });

  } catch (err) {
    console.error('Error sending trust request:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to send trust request',
      error: err.message
    });
  }
});

app.get('/api/trust-requests/pending', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  console.log(`Fetching pending requests for user ${userId}`);

  try {
    const pool = await sql.connect(config);

    // Verify user exists first
    const userExists = await pool.request()
      .input('UserID', sql.Int, userId)
      .query('SELECT 1 FROM Users WHERE UserID = @UserID');

    if (userExists.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Mark requests as viewed (but don't wait for completion)
    pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        UPDATE TrustRequests 
        SET Viewed = 1 
        WHERE RequestedID = @UserID AND Status = 'pending'
      `)
      .catch(err => console.error('Error marking as viewed:', err));

    // Fetch pending requests with requester info
    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT 
          tr.RequestID as requestId,
          tr.RequesterID as requesterId,
          u.FullName as requesterName,
          u.Username as requesterUsername,
          tr.Message as message,
          tr.RequestedAt as requestedAt,
          tr.Viewed as viewed
        FROM TrustRequests tr
        JOIN Users u ON tr.RequesterID = u.UserID
        WHERE tr.RequestedID = @UserID 
          AND tr.Status = 'pending'
        ORDER BY tr.RequestedAt DESC
      `);

    res.status(200).json({
      success: true,
      requests: result.recordset
    });

  } catch (err) {
    console.error('Error in pending requests:', {
      error: err.message,
      userId: userId,
      time: new Date().toISOString()
    });
    res.status(500).json({
      success: false,
      message: 'Failed to fetch requests',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});
app.post('/api/trust-requests/respond', requireAuth, async (req, res) => {
  const { requestId, accept } = req.body;
  const userId = req.session.user.id;
  console.log('Received trust requests response data:', {
    requestId,
    accept,
    userId
  });

  try {
    const pool = await sql.connect(config);

    // Verify the request exists and is pending
    const request = await pool.request()
      .input('RequestID', sql.Int, requestId)
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT RequesterID FROM TrustRequests 
        WHERE RequestID = @RequestID 
          AND RequestedID = @UserID 
          AND Status = 'pending'
      `);

    if (request.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Request not found or already responded'
      });
    }

    const requesterId = request.recordset[0].RequesterID;
    const newStatus = accept ? 'approved' : 'declined';

    // Update request status
    await pool.request()
      .input('RequestID', sql.Int, requestId)
      .input('Status', sql.VarChar(20), newStatus)
      .query(`
        UPDATE TrustRequests 
        SET Status = @Status, RespondedAt = dbo.GetSASTDateTime()
        WHERE RequestID = @RequestID
      `);

    if (accept) {
      // Create trusted relationship if accepted
      await pool.request()
        .input('TrustingUserID', sql.Int, requesterId)
        .input('TrustedUserID', sql.Int, userId)
        .input('RequestID', sql.Int, requestId)
        .query(`
          INSERT INTO TrustedContact 
          (TrustingUserID, TrustedUserID, RequestID)
          VALUES (@TrustingUserID, @TrustedUserID, @RequestID)
        `);
    }

    res.status(200).json({ success: true });

  } catch (err) {
    console.error('Error responding to trust request:', err);
    res.status(500).json({ success: false, message: 'Failed to respond to request' });
  }
});

app.get('/api/users/find', requireAuth, async (req, res) => {
  const { username } = req.query;
  console.log('Received user data found: ', req.body);

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('Username', sql.NVarChar(50), username)
      .query('SELECT UserID, FullName FROM Users WHERE Username = @Username');

    if (result.recordset.length > 0) {
      res.json({
        success: true,
        user: result.recordset[0]
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
  } catch (err) {
    console.error('Error finding user:', err);
    res.status(500).json({
      success: false,
      message: 'Error searching for user'
    });
  }
});

app.get('/api/trusted-contacts', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  console.log('getting trusted contacts for user:', userId);

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT 
          u.UserID as id,
          u.FullName as fullName,
          u.Email as email,
          u.PhoneNumber as phoneNumber,
          tr.RequestedAt as establishedAt
        FROM TrustedContact tc
        JOIN Users u ON tc.TrustedUserID = u.UserID
        LEFT JOIN TrustRequests tr ON tc.RequestID = tr.RequestID
        WHERE tc.TrustingUserID = @UserID
        ORDER BY tr.RequestedAt DESC
      `);

    res.status(200).json({
      success: true,
      contacts: result.recordset
    });
  } catch (err) {
    console.error('Error fetching trusted contacts:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch contacts',
      error: err.message
    });
  }
});
app.get('/trusted-contacts', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.BigInt, userId)
      .query(`SELECT * FROM [dbo].[TrustedContact] WHERE TrustingUserID=@userId`);
    res.status(200).json({
      success: true,
      contacts: result.recordset
    });
  } catch (err) {
    console.error('Error fetching trusted contacts:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch contacts',
      error: err.message
    });
  }
});

app.put('/reports/complete', async (req, res) => {
  const { reportId, reason } = req.body;
  console.log('Received Data', req.body);

  if (!reportId) {
    return res.status(400).json({
      success: false,
      message: 'Missing reportId in request body',
    });
  }

  try {
    const pool = await sql.connect(config);

    // Run both updates in parallel
    await Promise.all([
      pool.request()
        .input('reportId', sql.Int, reportId)
        .input('reason', sql.VarChar, reason)
        .query(`
          UPDATE Report
          SET Report_Status = @reason
          WHERE ReportID = @reportId
        `),
      pool.request()
        .input('reportId', sql.Int, reportId)
        .input('reason', sql.VarChar, reason)
        .query(`
          UPDATE Response
          SET res_Status = @reason
          WHERE reportID = @reportId
        `)
    ]);

    return res.status(200).json({
      success: true,
      message: 'Report and responses marked as completed.',
    });

  } catch (err) {
    console.error('Error updating report and responses:', err);

    // Avoid duplicate response error
    if (!res.headersSent) {
      return res.status(500).json({
        success: false,
        message: 'Failed to update report or responses',
        error: err.message,
      });
    }
  }
});

app.put('/response/cancel', async (req, res) => {
  const { reportId, userId } = req.body;

  if (!reportId || !userId) {
    return res.status(400).json({
      success: false,
      message: 'Missing reportId or userId in request body',
    });
  }

  try {
    const pool = await sql.connect(config);

    await pool.request()
      .input('reportId', sql.Int, reportId)
      .input('userId', sql.Int, userId)
      .query(`
        UPDATE Response
        SET res_Status = 'Cancelled'
        WHERE reportID = @reportId AND UserID = @userId
      `);

    res.status(200).json({
      success: true,
      message: `Response status set to 'Cancelled' for reportID ${reportId} and userID ${userId}.`,
    });
  } catch (err) {
    console.error('Error cancelling response:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to cancel response',
      error: err.message,
    });
  }
});


/*FEEDBACK ENDPOINTS************************************* */
app.post('/feedback/submit', async (req, res) => {
  const { reportId, rating, feedbackText } = req.body;

  // Validate input
  if (!reportId || !rating) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields (reportId or rating)',
    });
  }

  if (rating < 1 || rating > 5) {
    return res.status(400).json({
      success: false,
      message: 'Rating must be between 1 and 5',
    });
  }

  try {
    const pool = await sql.connect(config);

    // Check if feedback already exists for this report
    const existingFeedback = await pool.request()
      .input('reportId', sql.Int, reportId)
      .query(`
        SELECT 1 FROM Feedback 
        WHERE ReportID = @reportId
      `);

    if (existingFeedback.recordset.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Feedback already submitted for this report',
      });
    }

    // Insert the feedback (no need for ReporterID in the table)
    await pool.request()
      .input('reportId', sql.Int, reportId)
      .input('rating', sql.Int, rating)
      .input('feedbackText', sql.NVarChar(sql.MAX), feedbackText || null)
      .query(`
        INSERT INTO Feedback (ReportID, Rating, FeedbackText)
        VALUES (@reportId, @rating, @feedbackText)
      `);

    res.status(201).json({
      success: true,
      message: 'Feedback submitted successfully',
    });

  } catch (err) {
    console.error('Error submitting feedback:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to submit feedback',
      error: err.message,
    });
  }
});

app.get('/feedback/:reportId', async (req, res) => {
  const { reportId } = req.params;

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('reportId', sql.Int, reportId)
      .query(`
        SELECT 
          f.FeedbackID,
          f.Rating,
          f.FeedbackText,
          f.CreatedAt,
          r.ReporterID,
          u.FullName AS ReporterName
        FROM Feedback f
        JOIN Report r ON f.ReportID = r.ReportID
        JOIN Users u ON r.ReporterID = u.UserID
        WHERE f.ReportID = @reportId
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No feedback found for this report',
      });
    }

    res.status(200).json({
      success: true,
      feedback: result.recordset[0],
    });

  } catch (err) {
    console.error('Error fetching feedback:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch feedback',
      error: err.message,
    });
  }
});
app.get('/responses', async (req, res) => {
  const userId = parseInt(req.query.userId);

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ success: false, message: 'Missing or invalid userId query parameter' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool
      .request()
      .input('UserID', sql.Int, userId)
      .query('SELECT * FROM Response WHERE UserID = @UserID');

    res.json({ success: true, Responses: result.recordset });
  } catch (err) {
    console.error('SQL Error:', err);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

//group messages
app.post('/group/sendMessage', async (req, res) => {
  const { userID, msg, reportID } = req.body;

  if (!userID || !msg || !reportID) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const pool = await sql.connect(config);
    await pool.request()
      .input('userID', sql.Int, userID)
      .input('msg', sql.VarChar(sql.MAX), msg)
      .input('reportID', sql.Int, reportID)
      .query(`
        INSERT INTO [dbo].[groupMessage] (userID, msg, reportID, timeSent)
        VALUES (@userID, @msg, @reportID, dbo.GetSASTDateTime())
      `);

    res.status(201).json({ message: 'Message sent successfully' });
  } catch (err) {
    console.error('Error inserting message:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/group/getMessages', async (req, res) => {
  const reportID = req.query.reportID;

  if (!reportID) {
    return res.status(400).json({ error: 'Missing reportID in query params' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('reportID', sql.Int, reportID)
      .query(`
        SELECT * FROM groupMessage
        WHERE reportID = @reportID
        ORDER BY timeSent ASC
      `);

    res.json({ success: true, Messages: result.recordset });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/getFullName', async (req, res) => {
  const userID = req.query.userID;

  if (!userID) {
    return res.status(400).json({ error: 'Missing userID query parameter' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('UserID', sql.Int, userID)
      .query('SELECT FullName FROM Users WHERE UserID = @UserID');

    if (result.recordset.length > 0) {
      res.status(200).json({ fullName: result.recordset[0].FullName });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/trusted/count', async (req, res) => {
  const userId = parseInt(req.query.user);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user parameter' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool
      .request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT COUNT(*) AS TrustedCount
        FROM TrustedContact
        WHERE TrustingUserID = @userId
      `);

    const count = result.recordset[0].TrustedCount;
    res.json({ userId, trustedContacts: count });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


/************************************VOTING SYSTEM************************************** */
// Fixed Voting settings endpoints
// Voting settings endpoints
app.get('/api/voting/settings', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .query('SELECT TOP 1 * FROM VotingSettings ORDER BY SettingID DESC');

    // Return defaults if no settings exist
    if (result.recordset.length === 0) {
      return res.json({
        settingId: null,
        votingEnabled: false,
        startDate: null,
        endDate: null
      });
    }

    const settings = result.recordset[0];
    res.json({
      settingId: settings.SettingID,
      votingEnabled: !!settings.VotingEnabled,
      startDate: settings.StartDate,
      endDate: settings.EndDate
    });
  } catch (err) {
    console.error('Error fetching voting settings:', err);
    res.status(500).json({
      settingId: null,
      votingEnabled: false,
      startDate: null,
      endDate: null
    });
  }
});

app.post('/api/voting/settings', requireAuth, async (req, res) => {
  const { votingEnabled, startDate, endDate } = req.body;
  const updatedBy = req.session.user.id;

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('VotingEnabled', sql.Bit, votingEnabled)
      .input('StartDate', sql.DateTime, startDate)
      .input('EndDate', sql.DateTime, endDate)
      .input('UpdatedBy', sql.Int, updatedBy)
      .query(`
        INSERT INTO VotingSettings (VotingEnabled, StartDate, EndDate, UpdatedBy)
        OUTPUT INSERTED.SettingID
        VALUES (@VotingEnabled, @StartDate, @EndDate, @UpdatedBy)
      `);

    res.json({
      success: true,
      settingId: result.recordset[0].SettingID
    });
  } catch (err) {
    console.error('Error updating voting settings:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Nomination endpoints
app.post('/api/nominations', requireAuth, async (req, res) => {
  const { nomineeUsername, message } = req.body;
  const nominatedBy = req.session.user.id;

  if (!nomineeUsername) {
    return res.status(400).json({ error: 'Nominee username is required' });
  }

  try {
    const pool = await sql.connect(config);

    // First get the current active voting setting
    const settingsResult = await pool.request()
      .query('SELECT TOP 1 SettingID FROM VotingSettings ORDER BY SettingID DESC');

    if (settingsResult.recordset.length === 0) {
      return res.status(400).json({ error: 'No active voting session found' });
    }

    const currentSettingId = settingsResult.recordset[0].SettingID;

    // Find the nominee user
    const nomineeResult = await pool.request()
      .input('Username', sql.NVarChar(50), nomineeUsername)
      .query('SELECT UserID FROM Users WHERE Username = @Username');

    if (nomineeResult.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const nomineeId = nomineeResult.recordset[0].UserID;

    // Prevent self-nomination
    if (nomineeId === nominatedBy) {
      return res.status(400).json({ error: 'You cannot nominate yourself' });
    }

    // Check if nomination already exists for this voting session
    const existingNomination = await pool.request()
      .input('NomineeID', sql.Int, nomineeId)
      .input('NominatedBy', sql.Int, nominatedBy)
      .input('SettingID', sql.Int, currentSettingId)
      .query(`
        SELECT NominationID FROM Nominations 
        WHERE NomineeID = @NomineeID AND NominatedBy = @NominatedBy AND SettingID = @SettingID
      `);

    if (existingNomination.recordset.length > 0) {
      return res.status(400).json({ error: 'You have already nominated this person in the current voting session' });
    }

    // Create new nomination
    const result = await pool.request()
      .input('NomineeID', sql.Int, nomineeId)
      .input('NominatedBy', sql.Int, nominatedBy)
      .input('Message', sql.NVarChar(255), message || null)
      .input('SettingID', sql.Int, currentSettingId)
      .query(`
        INSERT INTO Nominations (NomineeID, NominatedBy, Message, SettingID)
        OUTPUT INSERTED.NominationID
        VALUES (@NomineeID, @NominatedBy, @Message, @SettingID)
      `);

    res.status(201).json({
      success: true,
      nominationId: result.recordset[0].NominationID
    });
  } catch (err) {
    console.error('Error creating nomination:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/nominations/pending', requireAuth, async (req, res) => {
  const userId = req.session.user.id;

  try {
    const pool = await sql.connect(config);

    // Get current voting session
    const settingsResult = await pool.request()
      .query('SELECT TOP 1 SettingID FROM VotingSettings ORDER BY SettingID DESC');

    if (settingsResult.recordset.length === 0) {
      return res.json([]);
    }

    const currentSettingId = settingsResult.recordset[0].SettingID;

    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .input('SettingID', sql.Int, currentSettingId)
      .query(`
        SELECT 
          n.NominationID,
          n.Message,
          n.NominatedAt,
          u.UserID as NominatorID,
          u.FullName as NominatorName,
          u.Username as NominatorUsername
        FROM Nominations n
        JOIN Users u ON n.NominatedBy = u.UserID
        WHERE n.NomineeID = @UserID 
          AND n.Status = 'pending' 
          AND n.SettingID = @SettingID
        ORDER BY n.NominatedAt DESC
      `);

    console.log('Pending nominations query result:', {
      userId,
      currentSettingId,
      recordCount: result.recordset.length,
      records: result.recordset
    });

    // Ensure all required fields are present and not null
    const validRecords = result.recordset.filter(record =>
      record.NominationID &&
      record.NominatorName &&
      record.NominatorUsername
    );

    console.log('Valid pending nominations:', validRecords);

    res.json(validRecords);
  } catch (err) {
    console.error('Error fetching pending nominations:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/nominations/respond', requireAuth, async (req, res) => {
  const { nominationId, accept } = req.body;
  const userId = req.session.user.id;

  try {
    const pool = await sql.connect(config);

    // Verify the nomination exists and is pending
    const nomination = await pool.request()
      .input('NominationID', sql.Int, nominationId)
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT NomineeID FROM Nominations 
        WHERE NominationID = @NominationID AND NomineeID = @UserID AND Status = 'pending'
      `);

    if (nomination.recordset.length === 0) {
      return res.status(404).json({ error: 'Nomination not found or already responded' });
    }

    // Update nomination status
    await pool.request()
      .input('NominationID', sql.Int, nominationId)
      .input('Status', sql.NVarChar(20), accept ? 'accepted' : 'declined')
      .query(`
        UPDATE Nominations 
        SET Status = @Status, RespondedAt = dbo.GetSASTDateTime()
        WHERE NominationID = @NominationID
      `);

    res.json({ success: true });
  } catch (err) {
    console.error('Error responding to nomination:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// CORRECTED Votes endpoint - This was the problematic one
app.post('/api/votes', requireAuth, async (req, res) => {
  const { nominationId } = req.body;
  const voterId = req.session.user.id;

  if (!nominationId) {
    return res.status(400).json({ error: 'Nomination ID is required' });
  }

  try {
    const pool = await sql.connect(config);

    // Get current voting session and check if voting is enabled
    const settingsResult = await pool.request()
      .query('SELECT TOP 1 SettingID, VotingEnabled, StartDate, EndDate FROM VotingSettings ORDER BY SettingID DESC');

    if (settingsResult.recordset.length === 0) {
      return res.status(403).json({ error: 'No voting session found' });
    }

    const votingSettings = settingsResult.recordset[0];

    if (!votingSettings.VotingEnabled) {
      return res.status(403).json({ error: 'Voting is not currently enabled' });
    }

    // Check if current time is within voting period
    const now = new Date();
    if (votingSettings.StartDate && new Date(votingSettings.StartDate) > now) {
      return res.status(403).json({ error: 'Voting has not started yet' });
    }

    if (votingSettings.EndDate && new Date(votingSettings.EndDate) < now) {
      return res.status(403).json({ error: 'Voting has ended' });
    }

    // Check if nomination exists, is accepted, and belongs to current voting session
    const nominationCheck = await pool.request()
      .input('NominationID', sql.Int, nominationId)
      .input('SettingID', sql.Int, votingSettings.SettingID)
      .query(`
        SELECT NomineeID FROM Nominations 
        WHERE NominationID = @NominationID 
          AND Status = 'accepted' 
          AND SettingID = @SettingID
      `);

    if (nominationCheck.recordset.length === 0) {
      return res.status(400).json({ error: 'Nomination not found, not accepted, or not part of current voting session' });
    }

    // Check if user is trying to vote for themselves
    const nomineeId = nominationCheck.recordset[0].NomineeID;
    if (nomineeId === voterId) {
      return res.status(400).json({ error: 'You cannot vote for yourself' });
    }

    // Check if user has already voted in this voting session
    const existingVote = await pool.request()
      .input('VoterID', sql.Int, voterId)
      .input('SettingID', sql.Int, votingSettings.SettingID)
      .query(`
        SELECT v.VoteID FROM Votes v
        JOIN Nominations n ON v.NomineeID = n.NominationID
        WHERE v.VoterID = @VoterID AND n.SettingID = @SettingID
      `);

    if (existingVote.recordset.length > 0) {
      return res.status(400).json({ error: 'You have already voted in this election' });
    }

    // Record the vote - using the corrected relationship
    await pool.request()
      .input('VoterID', sql.Int, voterId)
      .input('NominationID', sql.Int, nominationId)
      .query(`
        INSERT INTO Votes (VoterID, NomineeID)
        VALUES (@VoterID, @NominationID)
      `);

    res.json({ success: true });
  } catch (err) {
    console.error('Error recording vote:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Results endpoint
app.get('/api/votes/results', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    // Get current voting session
    const settingsResult = await pool.request()
      .query('SELECT TOP 1 SettingID FROM VotingSettings ORDER BY SettingID DESC');

    if (settingsResult.recordset.length === 0) {
      return res.json([]);
    }

    const currentSettingId = settingsResult.recordset[0].SettingID;

    const result = await pool.request()
      .input('SettingID', sql.Int, currentSettingId)
      .query(`
        SELECT 
          n.NominationID,
          u.UserID,
          u.FullName,
          u.Username,
          u.ProfilePhoto,
          COUNT(v.VoteID) AS VoteCount
        FROM Nominations n
        JOIN Users u ON n.NomineeID = u.UserID
        LEFT JOIN Votes v ON n.NominationID = v.NomineeID
        WHERE n.Status = 'accepted' AND n.SettingID = @SettingID
        GROUP BY n.NominationID, u.UserID, u.FullName, u.Username, u.ProfilePhoto
        ORDER BY VoteCount DESC, u.FullName ASC
      `);

    // Map the result to match frontend expectations
    const mappedResult = result.recordset.map(record => ({
      nominationId: record.NominationID,
      userId: record.UserID,
      fullName: record.FullName,
      username: record.Username,
      profilePhoto: record.ProfilePhoto,
      voteCount: record.VoteCount || 0
    }));

    res.json(mappedResult);
  } catch (err) {
    console.error('Error fetching vote results:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Current leader endpoint
app.get('/api/leader/current', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    // Get current voting session
    const settingsResult = await pool.request()
      .query('SELECT TOP 1 SettingID FROM VotingSettings ORDER BY SettingID DESC');

    if (settingsResult.recordset.length === 0) {
      return res.status(404).json({ error: 'No voting session found' });
    }

    const currentSettingId = settingsResult.recordset[0].SettingID;

    const result = await pool.request()
      .input('SettingID', sql.Int, currentSettingId)
      .query(`
        SELECT TOP 1
          u.UserID,
          u.FullName,
          u.Username,
          u.ProfilePhoto,
          COUNT(v.VoteID) AS VoteCount
        FROM Nominations n
        JOIN Users u ON n.NomineeID = u.UserID
        LEFT JOIN Votes v ON n.NominationID = v.NomineeID
        WHERE n.Status = 'accepted' AND n.SettingID = @SettingID
        GROUP BY u.UserID, u.FullName, u.Username, u.ProfilePhoto
        HAVING COUNT(v.VoteID) > 0
        ORDER BY VoteCount DESC
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'No current leader' });
    }

    const leader = result.recordset[0];
    res.json({
      userId: leader.UserID,
      fullName: leader.FullName,
      username: leader.Username,
      profilePhoto: leader.ProfilePhoto,
      voteCount: leader.VoteCount
    });
  } catch (err) {
    console.error('Error fetching current leader:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Current vote endpoint
app.get('/api/votes/current', requireAuth, async (req, res) => {
  const userId = req.session.user.id;

  try {
    const pool = await sql.connect(config);

    // Get current voting session
    const settingsResult = await pool.request()
      .query('SELECT TOP 1 SettingID FROM VotingSettings ORDER BY SettingID DESC');

    if (settingsResult.recordset.length === 0) {
      return res.json({ vote: null });
    }

    const currentSettingId = settingsResult.recordset[0].SettingID;

    const result = await pool.request()
      .input('VoterID', sql.Int, userId)
      .input('SettingID', sql.Int, currentSettingId)
      .query(`
        SELECT 
          v.VoteID,
          v.NomineeID as nominationId
        FROM Votes v
        JOIN Nominations n ON v.NomineeID = n.NominationID
        WHERE v.VoterID = @VoterID AND n.SettingID = @SettingID
      `);

    if (result.recordset.length === 0) {
      return res.json({ vote: null });
    }

    const vote = result.recordset[0];
    res.json({
      vote: {
        voteId: vote.VoteID,
        nominationId: vote.nominationId
      }
    });
  } catch (err) {
    console.error('Error fetching current vote:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/getResponse', async (req, res) => {
  try {
    const { UserID, reportID } = req.query;

    // Validate required parameters
    if (!UserID || !reportID) {
      return res.status(400).json({
        error: 'Missing required parameters',
        message: 'Both UserID and reportID are required'
      });
    }

    // Validate parameters are numbers
    if (isNaN(UserID) || isNaN(reportID)) {
      return res.status(400).json({
        error: 'Invalid parameter type',
        message: 'UserID and reportID must be valid integers'
      });
    }

    // SQL query to find ResponseID
    const query = `
            SELECT ResponseID 
            FROM Response 
            WHERE UserID = @UserID AND reportID = @reportID
        `;

    // Create a new request
    const request = new sql.Request();
    request.input('UserID', sql.Int, parseInt(UserID));
    request.input('reportID', sql.Int, parseInt(reportID));

    // Execute the query
    const result = await request.query(query);

    // Check if any records were found
    if (result.recordset.length === 0) {
      return res.status(404).json({
        error: 'Not found',
        message: 'No response found for the given UserID and reportID'
      });
    }

    // Return the ResponseID(s)
    const responseIDs = result.recordset.map(row => row.ResponseID);

    // If only one result, return it directly, otherwise return array
    if (responseIDs.length === 1) {
      res.json({
        success: true,
        ResponseID: responseIDs[0]
      });
    } else {
      res.json({
        success: true,
        ResponseIDs: responseIDs
      });
    }

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to retrieve response data'
    });
  }
});
// Create or update a misuse report
app.put('/api/mobile/misusereport', async (req, res) => {
  const { reportId, userId, responseId, misuseType, description } = req.body;

  // Validate required parameters
  if (!reportId || !userId || !responseId || !misuseType || !description) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  // Validate misuseType
  const allowedTypes = ['False Report', 'Suspicious Activity', 'Crime', 'Other'];
  if (!allowedTypes.includes(misuseType)) {
    return res.status(400).json({ error: 'Invalid misuse type' });
  }

  try {
    const pool = await sql.connect(config);
    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    try {
      // Check if misuse report already exists
      const checkResult = await transaction.request()
        .input('reportId', sql.Int, reportId)
        .query('SELECT MisuseID FROM MisuseReport WHERE ReportID = @reportId');

      let misuseId;

      if (checkResult.recordset.length > 0) {
        // Existing report - add new filer
        misuseId = checkResult.recordset[0].MisuseID;

        await transaction.request()
          .input('misuseId', sql.Int, misuseId)
          .input('responseId', sql.Int, responseId)
          .input('description', sql.VarChar(sql.MAX), description)
          .query(`
            INSERT INTO MisuseFiler (MisuseID, ResponseID, AdditionalDescription)
            VALUES (@misuseId, @responseId, @description)
          `);
      } else {
        // New report - create misuse report and first filer
        const createResult = await transaction.request()
          .input('reportId', sql.Int, reportId)
          .input('misuseType', sql.VarChar(50), misuseType)
          .input('description', sql.VarChar(sql.MAX), description)
          .query(`
            INSERT INTO MisuseReport (ReportID, MisuseType, InitialDescription)
            OUTPUT INSERTED.MisuseID
            VALUES (@reportId, @misuseType, @description)
          `);

        misuseId = createResult.recordset[0].MisuseID;

        await transaction.request()
          .input('misuseId', sql.Int, misuseId)
          .input('responseId', sql.Int, responseId)
          .query(`
            INSERT INTO MisuseFiler (MisuseID, ResponseID)
            VALUES (@misuseId, @responseId)
          `);
      }

      await transaction.commit();
      res.json({
        success: true,
        misuseId,
        message: checkResult.recordset.length > 0
          ? 'Added to existing misuse report'
          : 'Created new misuse report'
      });
    } catch (err) {
      await transaction.rollback();
      throw err;
    }
  } catch (err) {
    console.error('Error creating/updating misuse report:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});










//***************************Admin FUNCTIONALITY****************************************************** */
// register Admin
app.post('/register-admin', async (req, res) => {
  const {
    fullName,
    email,
    password,
    phoneNumber,
    imageBase64,
    acceptedTerms,
    darkmode = "No",
  } = req.body;

  const username = email.split("@")[0];
  const userType = 'admin';

  // Basic input validation
  if (!fullName || !email || !password || !phoneNumber || !imageBase64 || !darkmode || !acceptedTerms) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }

  try {
    const pool = await sql.connect(config);

    // Check for duplicate email
    const emailCheck = await pool.request()
      .input('Email', sql.VarChar, email)
      .query('SELECT UserID FROM Users WHERE Email = @Email');

    if (emailCheck.recordset.length > 0) {
      return res.status(409).json({ message: 'Email already registered.' });
    }

    // Use plain password (not secure)
    const plainPassword = password;

    // Insert new admin
    const usersResult = await pool.request()
      .input('FullName', sql.VarChar, fullName)
      .input('Email', sql.VarChar, email)
      .input('Username', sql.VarChar, username)
      .input('PhoneNumber', sql.VarChar, phoneNumber)
      .input('Passcode', sql.VarChar, plainPassword)
      .input('UserType', sql.VarChar, userType)
      .input('ProfilePhoto', sql.VarChar, imageBase64)
      .input('AcceptedTerms', sql.VarChar, acceptedTerms)
      .query(`
        INSERT INTO [dbo].[Users]
        (FullName, Email, Username, PhoneNumber, Passcode, UserType, CreatedAt, ProfilePhoto, AcceptedTerms)
        OUTPUT INSERTED.UserID
        VALUES
        (@FullName, @Email, @Username, @PhoneNumber, @Passcode, @UserType, dbo.GetSASTDateTime(), @ProfilePhoto, @AcceptedTerms)
      `);

    const userID = usersResult.recordset[0].UserID;

    if (userType === 'admin') {
      await pool.request()
        .input('UserID', sql.Int, userID)
        .input('DarkMode', sql.VarChar, 'No')
        .query(`
          INSERT INTO [dbo].[ADMIN] (UserID, DarkMode)
          VALUES (@UserID, @DarkMode)
        `);

      return res.status(201).json({ message: 'Admin registered successfully.', userID });
    }

  } catch (err) {
    console.error('Admin registration error:', err.message, err.stack);
    res.status(500).json({ message: 'Internal server error.' });
  }
});
//admin login
app.post('/login-admin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const pool = await sql.connect(config);
    const userResult = await pool.request()
      .input('Email', sql.VarChar, email)
      .query(`
        SELECT UserID, FullName, Email, Username, PhoneNumber, Passcode, UserType, CreatedAt, ProfilePhoto
        FROM [dbo].[Users]
        WHERE Email = @Email AND (UserType = 'admin' OR UserType = 'CommunityMember')
      `);

    if (userResult.recordset.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const user = userResult.recordset[0];

    // Plaintext password verification
    if (password !== user.Passcode) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Shared user fields
    const baseUserData = {
      UserID: user.UserID,
      FullName: user.FullName,
      Email: user.Email,
      Username: user.Username,
      PhoneNumber: user.PhoneNumber,
      UserType: user.UserType,
      CreatedAt: user.CreatedAt,
      ProfilePhoto: user.ProfilePhoto
    };

    if (user.UserType === "CommunityMember") {
      const communityResult = await pool.request()
        .input('UserID', sql.Int, user.UserID)
        .query(`
          SELECT Role, DOB, HomeAddress, TrustedContacts
          FROM [dbo].[CommunityMember]
          WHERE UserID = @UserID
        `);

      const communitym = communityResult.recordset[0] || {};
      const role = communitym.Role || 'Volunteer';

          
    if (role !== "CommunityLeader") {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

      res.json({
        success: true,
        user: {
          ...baseUserData,
          Role: role,
          DOB: communitym.DOB || null,
          HomeAddress: communitym.HomeAddress || null,
          TrustedContacts: communitym.TrustedContacts || null
        }
      });
    } else {
      const adminResult = await pool.request()
        .input('UserID', sql.Int, user.UserID)
        .query(`
          SELECT DarkMode
          FROM [dbo].[ADMIN]
          WHERE UserID = @UserID
        `);

      const darkMode = adminResult.recordset.length > 0
        ? adminResult.recordset[0].DarkMode
        : 'No';

      res.json({
        success: true,
        user: {
          ...baseUserData,
          DarkMode: darkMode
        }
      });
    }
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Get user data
app.get('/api/user/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId); // Convert to integer

  // Validate user ID
  if (isNaN(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('UserID', sql.BigInt, userId) // Use integer type
      .query(`
        SELECT u.*, a.DarkMode 
        FROM Users u
        LEFT JOIN ADMIN a ON u.UserID = a.UserID
        WHERE u.UserID = @UserID
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.recordset[0]);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.patch('/api/user/:userId', async (req, res) => {
  const { userId } = req.params;
  const { field, value } = req.body;
  const validFields = ['FullName', 'Email', 'Username', 'PhoneNumber'];

  console.log('Received PATCH request:', { userId, field, value }); // Add logging

  if (!validFields.includes(field)) {
    console.error('Invalid field requested:', field);
    return res.status(400).json({ error: `Invalid field: ${field}` });
  }

  try {
    const pool = await sql.connect(config);

    // Add parameterized query with better error handling
    const result = await pool.request()
      .input('UserID', sql.BigInt, userId)
      .input('Value', sql.NVarChar(sql.MAX), value) // Use MAX for potential long values
      .query(`UPDATE Users SET ${field} = @Value WHERE UserID = @UserID`);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true });
  } catch (err) {
    // Add detailed error logging
    console.error('Database update error:', {
      message: err.message,
      code: err.code,
      stack: err.stack
    });

    res.status(500).json({
      error: 'Update operation failed',
      details: err.message
    });
  }
});
app.patch('/api/user/:userId/photo', async (req, res) => {
  const { userId } = req.params;
  const { profilePhoto } = req.body;

  try {
    const pool = await sql.connect(config);
    await pool.request()
      .input('UserID', sql.BigInt, userId)
      .input('ProfilePhoto', sql.VarChar, profilePhoto)
      .query('UPDATE Users SET ProfilePhoto = @ProfilePhoto WHERE UserID = @UserID');

    res.json({ success: true });
  } catch (err) {
    console.error('Error updating profile photo:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.patch('/api/user/:userId/password', async (req, res) => {
  const { userId } = req.params;
  const { oldPassword, newPassword } = req.body;

  try {
    const pool = await sql.connect(config);

    // Get current password
    const userResult = await pool.request()
      .input('UserID', sql.BigInt, userId)
      .query('SELECT Passcode FROM Users WHERE UserID = @UserID');

    if (userResult.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const currentPassword = userResult.recordset[0].Passcode;

    // Verify old password (direct string comparison)
    if (oldPassword !== currentPassword) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Update password (store as plain text)
    await pool.request()
      .input('UserID', sql.Int, userId)
      .input('NewPassword', sql.VarChar, newPassword)
      .query('UPDATE Users SET Passcode = @NewPassword WHERE UserID = @UserID');

    res.json({ success: true });
  } catch (err) {
    console.error('Error updating password:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/admin/:userId/darkmode', async (req, res) => {
  const { userId } = req.params;
  const { darkMode } = req.body;

  try {
    const pool = await sql.connect(config);

    // Check if admin record exists
    const checkResult = await pool.request()
      .input('UserID', sql.BigInt, userId)
      .query('SELECT 1 FROM ADMIN WHERE UserID = @UserID');

    if (checkResult.recordset.length === 0) {
      // Create admin record if doesn't exist
      await pool.request()
        .input('UserID', sql.Int, userId)
        .input('DarkMode', sql.VarChar, darkMode)
        .query('INSERT INTO ADMIN (UserID, DarkMode) VALUES (@UserID, @DarkMode)');
    } else {
      // Update existing record
      await pool.request()
        .input('UserID', sql.Int, userId)
        .input('DarkMode', sql.VarChar, darkMode)
        .query('UPDATE ADMIN SET DarkMode = @DarkMode WHERE UserID = @UserID');
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Error updating dark mode:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
//******************BROADCAST MESSAGING ENDPOINTS ADMIN********************//
// POST a new message to a channel
app.post('/api/channels/:channelId/messages', async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) {
    return res.status(400).json({ error: 'Invalid channelId' });
  }

  const { senderId, content, images64 } = req.body;
  if (!senderId || !content) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Handle images64 (convert array to string or default to empty string)
  const imagesString = Array.isArray(images64) && images64.length > 0
    ? images64.join(';')
    : '';

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('ChannelID', sql.Int, channelId)
      .input('SenderID', sql.Int, senderId)
      .input('Content', sql.VarChar, content)
      .input('Images64', sql.NVarChar(sql.MAX), imagesString)
      .query(`
        INSERT INTO Messages (ChannelID, SenderID, Content, images64, SentAt)
        OUTPUT INSERTED.MessageID, INSERTED.SentAt, INSERTED.images64
        VALUES (@ChannelID, @SenderID, @Content, @Images64, dbo.GetSASTDateTime())
      `);

    if (result.recordset.length === 0) {
      throw new Error('Failed to insert message');
    }

    // Get sender name
    const senderResult = await pool.request()
      .input('UserID', sql.Int, senderId)
      .query('SELECT FullName FROM Users WHERE UserID = @UserID');

    // Convert stored images string back to array for response
    const storedImages = result.recordset[0].images64 || '';
    const imagesArray = storedImages ? storedImages.split(';') : [];

    // Get SAST timestamp for response
    const sastTimeResult = await pool.request()
      .query('SELECT dbo.GetSASTDateTime() AS sastTime');
    const sentAt = sastTimeResult.recordset[0].sastTime;

    const newMessage = {
      MessageID: result.recordset[0].MessageID,
      SenderID: senderId,
      SenderName: senderResult.recordset[0].FullName,
      Content: content,
      images64: imagesArray,
      SentAt: sentAt.toISOString()
    };

    res.status(201).json(newMessage);

    // 6. Background notification for community leaders
    setImmediate(async () => {
      try {
        const bgPool = await sql.connect(config);

        // Get community leaders
        const leaders = await bgPool.request()
          .query("SELECT UserID FROM CommunityMember WHERE Role = 'CommunityLeader'");

        if (leaders.recordset.length > 0) {
          // Create notification
          const notifResult = await bgPool.request()
            .input('NotificationType', sql.VarChar(50), 'BROADCAST')
            .input('EntityType', sql.VarChar(50), 'MESSAGE')
            .input('EntityID', sql.Int, newMessage.MessageID)
            .input('Title', sql.VarChar(255), 'New Broadcast Alert')
            .input('Message', sql.VarChar(sql.MAX), `New emergency alert: ${content.substring(0, 100)}...`)
            .query(`
              INSERT INTO Notifications 
              (NotificationType, EntityType, EntityID, Title, Message)
              OUTPUT INSERTED.NotificationID
              VALUES (@NotificationType, @EntityType, @EntityID, @Title, @Message)
            `);

          const notificationId = notifResult.recordset[0].NotificationID;

          // Add recipients
          const values = leaders.recordset.map(leader =>
            `(${notificationId}, ${leader.UserID})`
          ).join(',');

          await bgPool.request().query(`
            INSERT INTO NotificationRecipients (NotificationID, UserID)
            VALUES ${values}
          `);
        }
        await bgPool.close();
      } catch (err) {
        console.error('Background task: Failed to create broadcast notification:', err);
      }
    });

  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// GET messages for a channel
app.get('/api/channels/:channelId/messages', async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) {
    return res.status(400).json({ error: 'Invalid channelId' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('ChannelID', sql.Int, channelId)
      .query(`
        SELECT TOP 50 
          m.MessageID, 
          m.SenderID, 
          u.FullName AS SenderName, 
          m.Content, 
          COALESCE(m.images64, '') AS images64,  
          m.SentAt
        FROM Messages m
        JOIN Users u ON m.SenderID = u.UserID
        WHERE m.ChannelID = @ChannelID
        AND m.isActive = 'Yes'
        ORDER BY m.SentAt DESC
      `);

    res.json({
      messages: result.recordset.map(msg => {
        // Handle image conversion safely
        let imagesArray = [];
        try {
          if (msg.images64 && msg.images64.trim() !== '') {
            imagesArray = msg.images64.split(';').filter(Boolean);
          }
        } catch (e) {
          console.error('Error parsing images:', e);
        }

        return {
          ...msg,
          images64: imagesArray,
          SentAt: new Date(msg.SentAt).toISOString()
        };
      })
    });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({
      error: 'Internal server error',
      details: err.message
    });
  }
});

// GET disabled messages
app.get('/api/channels/:channelId/messages/disabled', async (req, res) => {
  try {
    const channelId = parseInt(req.params.channelId, 10);
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('ChannelID', sql.Int, channelId)
      .query(`
        SELECT TOP 50 
          m.MessageID, 
          m.SenderID, 
          u.FullName AS SenderName, 
          m.Content, 
          COALESCE(m.images64, '') AS images64,  
          m.SentAt
        FROM Messages m
        JOIN Users u ON m.SenderID = u.UserID
        WHERE m.ChannelID = @ChannelID
          AND m.isActive = 'No'
        ORDER BY m.SentAt DESC
      `);

    res.json({
      messages: result.recordset.map(msg => {
        // Handle image conversion safely
        let imagesArray = [];
        try {
          if (msg.images64 && msg.images64.trim() !== '') {
            imagesArray = msg.images64.split(';').filter(Boolean);
          }
        } catch (e) {
          console.error('Error parsing images:', e);
        }

        return {
          ...msg,
          images64: imagesArray,
          SentAt: new Date(msg.SentAt).toISOString()
        };
      })
    });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({
      error: 'Internal server error',
      details: err.message
    });
  }
});

// Updated disable message endpoint with notification
app.patch('/api/messages/:messageId/disable', async (req, res) => {
  try {
    const messageId = parseInt(req.params.messageId, 10);
    const pool = await sql.connect(config);

    // Get message details
    const messageResult = await pool.request()
      .input('MessageID', sql.Int, messageId)
      .query('SELECT Content, SenderID FROM Messages WHERE MessageID = @MessageID');

    if (messageResult.recordset.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const content = messageResult.recordset[0].Content;
    const senderId = messageResult.recordset[0].SenderID;

    // Disable the message
    await pool.request()
      .input('MessageID', sql.Int, messageId)
      .query('UPDATE Messages SET isActive = \'No\' WHERE MessageID = @MessageID');

    // Create notification for community leaders
    const leaders = await pool.request()
      .query("SELECT UserID FROM CommunityMember WHERE Role = 'CommunityLeader'");

    if (leaders.recordset.length > 0) {
      // Create notification
      const notifResult = await pool.request()
        .input('NotificationType', sql.VarChar(50), 'MODERATION_ACTION')
        .input('EntityType', sql.VarChar(50), 'MESSAGE')
        .input('EntityID', sql.Int, messageId)
        .input('Title', sql.VarChar(255), 'Message Disabled')
        .input('Message', sql.VarChar(sql.MAX), `A message has been disabled: "${content.substring(0, 100)}${content.length > 100 ? '...' : ''}"`)
        .query(`
          INSERT INTO Notifications 
          (NotificationType, EntityType, EntityID, Title, Message)
          OUTPUT INSERTED.NotificationID
          VALUES (@NotificationType, @EntityType, @EntityID, @Title, @Message)
        `);

      const notificationId = notifResult.recordset[0].NotificationID;

      // Add recipients
      const values = leaders.recordset.map(leader =>
        `(${notificationId}, ${leader.UserID})`
      ).join(',');

      await pool.request().query(`
        INSERT INTO NotificationRecipients (NotificationID, UserID)
        VALUES ${values}
      `);
    }

    res.status(200).json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to disable message' });
  }
});

// Updated restore message endpoint with notification
app.patch('/api/messages/:messageId/restore', async (req, res) => {
  try {
    const messageId = parseInt(req.params.messageId, 10);
    const pool = await sql.connect(config);

    // Get message details
    const messageResult = await pool.request()
      .input('MessageID', sql.Int, messageId)
      .query('SELECT Content, SenderID FROM Messages WHERE MessageID = @MessageID');

    if (messageResult.recordset.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const content = messageResult.recordset[0].Content;
    const senderId = messageResult.recordset[0].SenderID;

    // Restore the message
    await pool.request()
      .input('MessageID', sql.Int, messageId)
      .query('UPDATE Messages SET isActive = \'Yes\' WHERE MessageID = @MessageID');

    // Create notification for community leaders
    const leaders = await pool.request()
      .query("SELECT UserID FROM CommunityMember WHERE Role = 'CommunityLeader'");

    if (leaders.recordset.length > 0) {
      // Create notification
      const notifResult = await pool.request()
        .input('NotificationType', sql.VarChar(50), 'MODERATION_ACTION')
        .input('EntityType', sql.VarChar(50), 'MESSAGE')
        .input('EntityID', sql.Int, messageId)
        .input('Title', sql.VarChar(255), 'Message Restored')
        .input('Message', sql.VarChar(sql.MAX), `A message has been restored: "${content.substring(0, 100)}${content.length > 100 ? '...' : ''}"`)
        .query(`
          INSERT INTO Notifications 
          (NotificationType, EntityType, EntityID, Title, Message)
          OUTPUT INSERTED.NotificationID
          VALUES (@NotificationType, @EntityType, @EntityID, @Title, @Message)
        `);

      const notificationId = notifResult.recordset[0].NotificationID;

      // Add recipients
      const values = leaders.recordset.map(leader =>
        `(${notificationId}, ${leader.UserID})`
      ).join(',');

      await pool.request().query(`
        INSERT INTO NotificationRecipients (NotificationID, UserID)
        VALUES ${values}
      `);
    }

    res.status(200).json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to restore message' });
  }
});

// Mark all messages as read
app.post('/api/messages/:UserID/mark-all-read', async (req, res) => {
  const userId = parseInt(req.params.UserID, 10);
  const channelId = 1; // Melville Emergency Channel

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid channelId' });
  }

  try {
    const pool = await sql.connect(config);

    await pool.request()
      .input('UserID', sql.Int, userId)
      .input('ChannelID', sql.Int, channelId)
      .query(`
        INSERT INTO MessageReadStatus (MessageID, UserID, ReadAt)
        SELECT m.MessageID, @UserID, dbo.GetSASTDateTime()
        FROM Messages m
        LEFT JOIN MessageReadStatus r ON m.MessageID = r.MessageID AND r.UserID = @UserID
        WHERE m.ChannelID = @ChannelID
          AND m.SenderID != @UserID
          AND r.MessageID IS NULL
      `);

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Error marking all as read:', err);
    res.status(500).json({ success: false, message: 'Failed to mark messages as read' });
  }
});

// Mark message as read
app.post('/api/messages/:UserID/read', async (req, res) => {
  const userId = parseInt(req.params.UserID, 10);
  const { messageId } = req.body;

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid channelId' });
  }

  try {
    const pool = await sql.connect(config);

    // First check if the message exists
    const messageExists = await pool.request()
      .input('MessageID', sql.Int, messageId)
      .query('SELECT 1 FROM Messages WHERE MessageID = @MessageID');

    if (messageExists.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Check if already marked as read to avoid duplicates
    const alreadyRead = await pool.request()
      .input('MessageID', sql.Int, messageId)
      .input('UserID', sql.Int, userId)
      .query('SELECT 1 FROM MessageReadStatus WHERE MessageID = @MessageID AND UserID = @UserID');

    if (alreadyRead.recordset.length > 0) {
      return res.status(200).json({
        success: true,
        message: 'Message was already marked as read'
      });
    }

    // Insert with current timestamp
    await pool.request()
      .input('MessageID', sql.Int, messageId)
      .input('UserID', sql.Int, userId)
      .query(`
                INSERT INTO MessageReadStatus (MessageID, UserID, ReadAt)
                VALUES (@MessageID, @UserID, dbo.GetSASTDateTime())
            `);

    res.status(200).json({
      success: true,
      readAt: new Date().toISOString()
    });

  } catch (err) {
    console.error('Error marking message as read:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to mark message as read',
      error: err.message
    });
  }
});

// GET /api/messages/unread-count
app.get('/api/messages/:UserID/unread-count', requireAuth, async (req, res) => {
  const userId = parseInt(req.params.UserID, 10);
  const channelId = 1; // Melville Emergency 

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid channelId' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .input('ChannelID', sql.Int, channelId)
      .query(`
                SELECT COUNT(*) as count
                FROM Messages m
                LEFT JOIN MessageReadStatus r ON m.MessageID = r.MessageID AND r.UserID = @UserID
                WHERE m.ChannelID = @ChannelID
                AND m.SenderID != @UserID  -- Only count messages from others
                AND r.MessageID IS NULL    -- Only count unread messages
            `);

    res.status(200).json({
      success: true,
      count: result.recordset[0].count
    });

  } catch (err) {
    console.error('Error counting unread messages:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to count unread messages',
      error: err.message
    });
  }
});

// GET /api/sleep-status/:userId - Check if user is on break with broadcast restrictions
app.get('/api/sleep-status/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid user ID'
    });
  }

  try {
    const pool = await sql.connect(config);

    // Query the Sleep table for the user's current sleep status
    // Using SAST datetime function to compare with EndTime
    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT TOP 1 
          UserID, 
          OnBreak, 
          SleepType, 
          EndTime,
          CASE 
            WHEN EndTime IS NOT NULL AND dbo.GetSASTDateTime() > EndTime THEN 'No'
            ELSE OnBreak
          END AS CurrentOnBreak
        FROM Sleep 
        WHERE UserID = @UserID
        ORDER BY EndTime DESC
      `);

    if (result.recordset.length === 0) {
      // No sleep record found - user is not restricted
      return res.json({
        success: true,
        sleepData: null,
        message: 'No sleep restrictions found'
      });
    }

    const sleepData = result.recordset[0];

    // Return the current sleep status with time-adjusted OnBreak status
    res.json({
      success: true,
      sleepData: {
        UserID: sleepData.UserID,
        OnBreak: sleepData.CurrentOnBreak,
        SleepType: sleepData.SleepType,
        EndTime: sleepData.EndTime
      },
      message: 'Sleep status retrieved successfully'
    });

  } catch (err) {
    console.error('Error checking sleep status:', err);
    res.status(500).json({
      success: false,
      message: 'Server error checking sleep status'
    });
  }
});
app.get('/isUserOnSleep', async (req, res) => {
  const userID = parseInt(req.query.userID);

  if (!userID || isNaN(userID)) {
    return res.status(400).json({ success: false, message: 'Invalid or missing userID' });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userID)
      .query(`
        SELECT TOP 1 EndTime
        FROM Sleep
        WHERE UserID = @UserID
          AND OnBreak = 'Yes'
          AND SleepType IN ('Report', 'Both')
          AND EndTime > dbo.GetSASTDateTime()
        ORDER BY EndTime DESC
      `);

    if (result.recordset.length > 0) {
      return res.json({ success: true, onSleep: true, endTime: result.recordset[0].EndTime });
    } else {
      return res.json({ success: true, onSleep: false });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/report/checkOngoing', async (req, res) => {
  const { userID } = req.query;

  if (!userID) {
    return res.status(400).json({ error: "Missing userID parameter" });
  }

  try {
    let pool = await sql.connect(config);

    let result = await pool.request()
      .input("userID", sql.Int, userID)
      .query(`
        SELECT TOP 1 ReportID 
        FROM Report
        WHERE ReporterID = @userID AND Report_Status = 'On-going'
      `);

    if (result.recordset.length > 0) {
      return res.json({ ongoing: true, reportID: result.recordset[0].ReportID });
    } else {
      return res.json({ ongoing: false, reportID: null });
    }

  } catch (err) {
    console.error("Database error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});




//******************Manage users ENDPOINTS ADMIN********************//

// Get all volunteers (community members with role "Volunteer") dbo.GetSASTDateTime()
app.get('/api/volunteers', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    // First, update expired sleep statuses
    await pool.request().query(`
      UPDATE Sleep 
      SET OnBreak = 'No'
      WHERE OnBreak = 'Yes' AND EndTime <= dbo.GetSASTDateTime()
    `);

    const result = await pool.request().query(`
      SELECT 
        u.UserID,
        u.FullName,
        u.Email,
        u.PhoneNumber,
        (SELECT COUNT(*) FROM Report WHERE ReporterID = u.UserID) AS requests,
        (SELECT COUNT(*) FROM Response WHERE UserID = u.UserID) AS responses,
        CASE 
          WHEN EXISTS (
            SELECT 1 FROM Sleep 
            WHERE UserID = u.UserID 
            AND OnBreak = 'Yes' 
            AND EndTime > dbo.GetSASTDateTime()
          ) THEN 0 
          ELSE 1 
        END AS isActive
      FROM Users u
      INNER JOIN CommunityMember cm ON u.UserID = cm.UserID
      WHERE cm.Role = 'Volunteer'
    `);

    res.json({ volunteers: result.recordset });
  } catch (err) {
    console.error('Error fetching volunteers:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check and update expired sleep statuses
app.post('/api/sleep/check-expired', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request().query(`
      UPDATE Sleep 
      SET OnBreak = 'No'
      OUTPUT INSERTED.UserID
      WHERE OnBreak = 'Yes' AND EndTime <= dbo.GetSASTDateTime()
    `);

    res.json({
      updatedUsers: result.recordset.map(row => row.UserID),
      message: `${result.rowsAffected} users reactivated`
    });
  } catch (err) {
    console.error('Error updating sleep status:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get misuse reports for a user
app.get('/api/misuses/user/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT 
          mr.MisuseID,
          mr.MisuseType,
          mr.InitialDescription,
          mr.CreatedAt,
          mr.MisuseStatus,
          r.emerDescription AS ReportDescription,
          COUNT(mf.FilerID) AS FilerCount,
          STRING_AGG(u.FullName, ', ') WITHIN GROUP (ORDER BY mf.FiledAt) AS Filers
        FROM MisuseReport mr
        INNER JOIN Report r ON mr.ReportID = r.ReportID
        INNER JOIN MisuseFiler mf ON mr.MisuseID = mf.MisuseID
        INNER JOIN Response res ON mf.ResponseID = res.ResponseID
        INNER JOIN Users u ON res.UserID = u.UserID
        WHERE r.ReporterID = @userId
        GROUP BY 
          mr.MisuseID, 
          mr.MisuseType, 
          mr.InitialDescription, 
          mr.CreatedAt, 
          mr.MisuseStatus,
          r.emerDescription
        ORDER BY mr.CreatedAt DESC
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching misuses for user:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get misuse counts per user
app.get('/api/misuses/counts', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.request().query(`
      SELECT 
        r.ReporterID AS UserID, 
        COUNT(DISTINCT mr.MisuseID) AS misuseCount
      FROM MisuseReport mr
      INNER JOIN Report r ON mr.ReportID = r.ReportID
      GROUP BY r.ReporterID
    `);

    const counts = {};
    result.recordset.forEach(row => {
      counts[row.UserID] = row.misuseCount;
    });

    res.json(counts);
  } catch (err) {
    console.error('Error fetching misuse counts:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Backend endpoint
app.get('/api/misuse/filers/:misuseId', async (req, res) => {
  const misuseId = parseInt(req.params.misuseId, 10);

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('misuseId', sql.Int, misuseId)
      .query(`
        SELECT 
          u.FullName,
          u.Email,
          mf.AdditionalDescription,
          mf.FiledAt
        FROM MisuseFiler mf
        INNER JOIN Response res ON mf.ResponseID = res.ResponseID
        INNER JOIN Users u ON res.UserID = u.UserID
        WHERE mf.MisuseID = @misuseId
        ORDER BY mf.FiledAt
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching filers:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get flag details for a specific user
app.get('/api/flags/user/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId, 10); // Get from query param

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT 
      fm.FlagID as id,
      fm.Reason as type,
      fm.FlaggedAt as created_at,
      fm.FlaggedStatus as status,
      'System' as reporter_name,
      fm.Reason as description
    FROM FlaggedMessages fm
    INNER JOIN Messages m ON fm.MessageID = m.MessageID
    WHERE fm.UserID = @userId
    ORDER BY fm.FlaggedAt DESC
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching flags for user:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get flag counts for all users
app.get('/api/flags/counts', async (req, res) => {
  try {
    // Connect to the database using your existing pattern
    const pool = await sql.connect(config);

    // Query to count flags per user
    const query = `
      SELECT CAST(UserID AS VARCHAR) AS UserID, COUNT(FlagID) AS flagCount
      FROM FlaggedMessages
      GROUP BY UserID
    `;

    const result = await pool.request().query(query);

    // Convert to { UserID: count } mapping
    const countsMap = {};
    result.recordset.forEach(row => {
      countsMap[row.UserID] = row.flagCount;
    });

    res.json(countsMap);
  } catch (err) {
    console.error('Error fetching flag counts:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add this endpoint to your server.js file
app.get('/api/community/count', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request().query(`
      SELECT COUNT(UserID) AS userCount
      FROM Users
    `);

    const userCount = result.recordset[0].userCount;

    res.json({
      success: true,
      count: userCount
    });

  } catch (err) {
    console.error('Error fetching user count:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// put users to sleep
app.post('/api/sleep', async (req, res) => {
  const { userId, durationHours, sleepType } = req.body;

  if (!userId || !durationHours || !sleepType) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const pool = await sql.connect(config);

    // Get current UTC time
    const utcNow = new Date();

    // Convert to SAST (UTC+2)
    const startTime = new Date(utcNow);
    startTime.setHours(startTime.getHours() + 2);

    // Calculate end time in SAST
    const endTime = new Date(startTime);
    endTime.setHours(endTime.getHours() + durationHours);

    await pool.request()
      .input('UserID', sql.Int, userId)
      .input('OnBreak', sql.VarChar, 'Yes')
      .input('SleepType', sql.VarChar, sleepType)
      .input('StartTime', sql.DateTime, startTime)
      .input('EndTime', sql.DateTime, endTime)
      .query(`
        INSERT INTO Sleep (UserID, OnBreak, SleepType, StartTime, EndTime)
        VALUES (@UserID, @OnBreak, @SleepType, @StartTime, @EndTime)
      `);

    res.json({ success: true });
  } catch (err) {
    console.error('Error putting user to sleep:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//get report
app.get('/getReportWithReporter', async (req, res) => {
  const { id } = req.query;

  if (!id) {
    return res.status(400).json({
      success: false,
      message: 'Report ID is required',
    });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('ReportID', sql.Int, id)
      .query(`
        SELECT 
          r.ReportID,
          r.emergencyType,
          r.emerDescription,
          r.media_Photo,
          r.media_Voice,
          r.sharedWith,
          r.Report_Location,
          r.Report_Status,
          r.ReporterID,
          r.dateReported,

          u.FullName,
          u.Email,
          u.Username,
          u.PhoneNumber,
          u.UserType,
          u.ProfilePhoto
        FROM Report r
        INNER JOIN Users u ON r.ReporterID = u.UserID
        WHERE r.ReportID = @ReportID
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No report found for the given ID',
      });
    }

    const row = result.recordset[0];

    const response = {
      Report: {
        ReportID: row.ReportID,
        EmergencyType: row.emergencyType,
        EmerDescription: row.emerDescription,
        MediaPhoto: row.media_Photo,
        MediaVoice: row.media_Voice,
        SharedWith: row.sharedWith,
        Report_Location: row.Report_Location,
        Report_Status: row.Report_Status,
        ReporterID: row.ReporterID,
        dateReported: row.dateReported,
      },
      Reporter: {
        FullName: row.FullName,
        Email: row.Email,
        Username: row.Username,
        PhoneNumber: row.PhoneNumber,
        UserType: row.UserType,
        ProfilePhoto: row.ProfilePhoto,
      }
    };

    res.status(200).json({
      success: true,
      data: response,
    });

  } catch (error) {
    console.error("Error fetching report and reporter:", error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});
//get response time for emergency time
app.get('/getAverageResponseTimeByEmergencyType', async (req, res) => {
  const { emergencyType } = req.query; // expects ?emergencyType=Fire

  try {
    const pool = await sql.connect(config);

    if (!emergencyType) {
      return res.status(400).json({ message: "Missing emergencyType in query." });
    }

    const result = await pool.request()
      .input('emergencyType', sql.VarChar, emergencyType)
      .query(`
        SELECT 
          AVG(DATEDIFF(MINUTE, r.dateReported, res.dateAccepted)) as averageResponseTimeMinutes,
          COUNT(DISTINCT r.ReportID) as totalReports,
          COUNT(DISTINCT res.ResponseID) as respondedReports
        FROM Report r
        LEFT JOIN Response res ON r.ReportID = res.reportID
        WHERE r.emergencyType = @emergencyType 
          AND res.dateAccepted IS NOT NULL
      `);

    res.status(200).json({
      success: true,
      emergencyType,
      data: result.recordset[0] // returns { averageResponseTimeMinutes, totalReports, respondedReports }
    });

  } catch (err) {
    console.error("Error fetching average response time:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

//Get comunity memebers
app.get('/getCommunityMembers', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request().query(`
      SELECT 
        u.UserID,
        u.FullName,
        u.Email,
        u.Username,
        u.PhoneNumber,
        u.UserType,
        u.CreatedAt,
        cm.Role,
        cm.DOB,
        cm.HomeAddress
      FROM Users u
      INNER JOIN CommunityMember cm ON u.UserID = cm.UserID
    `);

    const members = result.recordset;
    const count = members.length;

    if (count === 0) {
      return res.status(200).json({
        success: true,
        message: 'No community members found.',
        count: 0,
        CommunityMembers: [],
      });
    }

    res.status(200).json({
      success: true,
      message: `${count} community member(s) found.`,
      count,
      CommunityMembers: members,
    });

  } catch (err) {
    console.error('Error fetching community members:', err);
    res.status(500).json({
      success: false,
      message: 'Internal server error.',
    });
  }
});
//
app.get('/topFiveResponders', async (req, res) => {
  let pool;
  try {

    pool = await sql.connect(config);

    const result = await pool.request().query(`
      SELECT TOP 5
          u.UserID,
          u.FullName,
          u.ProfilePhoto,
          COUNT(r.ResponseID) AS ResponseCount
      FROM [dbo].[Response] r
      JOIN [dbo].[Users] u ON r.UserID = u.UserID
      GROUP BY u.UserID, u.FullName, u.ProfilePhoto
      ORDER BY ResponseCount DESC;
    `);

    res.json({
      success: true,
      data: result.recordset
    });
  } catch (err) {
    console.error('Detailed DB error:', {
      message: err.message,
      code: err.code,
      stack: err.stack
    });

    res.status(500).json({
      success: false,
      error: 'Server error fetching top responders',
      // Only include details in development environment
      detail: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  } finally {
    if (pool) await pool.close();
  }
});

app.get('/reports/count', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .query(`SELECT COUNT(*) AS ReportCount FROM [dbo].[Report]`);

    const count = result.recordset[0].ReportCount;

    res.status(200).json({
      success: true,
      message: 'Report count retrieved successfully.',
      count: count
    });

  } catch (err) {
    console.error('Error counting reports:', err);
    res.status(500).json({
      success: false,
      message: 'Internal server error.'
    });
  }
});

app.get('/reports/count/completed', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .query(`SELECT COUNT(*) AS CompletedCount FROM [dbo].[Report] WHERE Report_Status = 'Completed'`);

    const count = result.recordset[0].CompletedCount;

    res.status(200).json({
      success: true,
      message: 'Completed report count retrieved successfully.',
      count: count
    });

  } catch (err) {
    console.error('Error counting completed reports:', err);
    res.status(500).json({
      success: false,
      message: 'Internal server error.'
    });
  }
});
//Location thing
const suburbBounds = [
  { name: 'Westdene', minLat: -26.1830, maxLat: -26.1660, minLng: 27.9900, maxLng: 28.0050 },
  { name: 'Melville', minLat: -26.1780, maxLat: -26.1570, minLng: 27.9840, maxLng: 28.0120 },
  { name: 'Auckland Park', minLat: -26.1860, maxLat: -26.1660, minLng: 27.9740, maxLng: 27.9940 },
  { name: 'Rossmore', minLat: -26.1890, maxLat: -26.1730, minLng: 27.9890, maxLng: 28.0070 },
  { name: 'Hursthill', minLat: -26.1910, maxLat: -26.1780, minLng: 27.9820, maxLng: 27.9940 },
  { name: 'Brixton', minLat: -26.2000, maxLat: -26.1800, minLng: 27.9700, maxLng: 27.9900 },
  { name: 'Richmond', minLat: -26.1900, maxLat: -26.1740, minLng: 27.9600, maxLng: 27.9800 },
  { name: 'Johannesburg Ward 88', minLat: -26.1700, maxLat: -26.1500, minLng: 27.9800, maxLng: 28.0000 },
  { name: 'Johannesburg Ward 69', minLat: -26.2000, maxLat: -26.1800, minLng: 27.9600, maxLng: 27.9800 },
  { name: 'Johannesburg Ward 87', minLat: -26.1900, maxLat: -26.1700, minLng: 27.9900, maxLng: 28.0100 }
];

function getSuburbFromCoordinates(lat, lng) {
  for (const s of suburbBounds) {
    if (lat >= s.minLat && lat <= s.maxLat && lng >= s.minLng && lng <= s.maxLng) {
      return s.name;
    }
  }
  return 'Unknown Area';
}

app.get('/getSuburbsByType', async (req, res) => {
  const type = req.query.type;

  if (!type) {
    return res.status(400).json({ success: false, error: 'Missing report type in query parameter' });
  }

  try {
    const pool = await sql.connect(config);
    const request = pool.request();
    request.input("type", sql.VarChar, type);

    const result = await request.query(`
      SELECT ReportID, Report_Location
      FROM [dbo].[Report] 
      WHERE emergencyType = @type
    `);

    const reportsWithSuburbs = result.recordset.map(report => {
      let suburb = 'Invalid Location';
      if (report.Report_Location && typeof report.Report_Location === 'string') {
        const parts = report.Report_Location.split(';');
        if (parts.length === 2) {
          const lat = parseFloat(parts[0]);
          const lng = parseFloat(parts[1]);
          if (!isNaN(lat) && !isNaN(lng)) {
            suburb = getSuburbFromCoordinates(lat, lng);
          }
        }
      }
      return {
        ReportID: report.ReportID,
        Report_Location: report.Report_Location,
        suburb
      };
    });

    // Unique suburbs
    const uniqueSuburbs = [...new Set(reportsWithSuburbs.map(r => r.suburb))];

    // Count per suburb
    const suburbCounts = {};
    for (const r of reportsWithSuburbs) {
      suburbCounts[r.suburb] = (suburbCounts[r.suburb] || 0) + 1;
    }

    res.status(200).json({
      success: true,
      reports: reportsWithSuburbs,
      uniqueSuburbs,
      suburbCounts,
      totalReports: reportsWithSuburbs.length,
      uniqueSuburbCount: uniqueSuburbs.length
    });

  } catch (err) {
    console.error('Error fetching reports:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});


//
app.get('/getReportsByUser', async (req, res) => {
  const { userID } = req.query;

  if (!userID || isNaN(userID)) {
    return res.status(400).json({
      success: false,
      message: 'Valid userID is required',
    });
  }

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('UserID', sql.Int, userID)
      .query(`
        SELECT 
          ReportID, 
          emergencyType, 
          emerDescription, 
          Report_Location, 
          Report_Status, 
          dateReported
        FROM Report
        WHERE ReporterID = @UserID
        ORDER BY dateReported DESC
      `);

    const reports = result.recordset;

    if (reports.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No reports found for this user',
      });
    }

    res.status(200).json({
      success: true,
      count: reports.length,
      reports,
    });

  } catch (error) {
    console.error("Error fetching reports by user:", error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

app.get('/getcountbyemergency', async (req, res) => {
  try {
    const { type } = req.query;
    if (!type) {
      return res.status(400).json({ success: false, error: 'Missing report type' });
    }

    const pool = await sql.connect(config);
    const result = await pool.request()
      .input("type", sql.VarChar, type)
      .query(`
        SELECT 
          suburbName,
          Report_Status,
          COUNT(*) AS report_count
        FROM [dbo].[Report]
        WHERE emergencyType = @type
        GROUP BY suburbName, Report_Status
        ORDER BY suburbName, Report_Status
      `);

    return res.status(200).json({
      success: true,
      data: result.recordset
    });

  } catch (error) {
    console.error("Error fetching report counts:", error);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});



app.get('/getReportsByTypeWithSuburbs', async (req, res) => {
  const { type } = req.query;
  if (!type) {
    return res.status(400).json({ success: false, error: 'Missing report type' });
  }

  try {
    const pool = await poolPromise;
    const result = await pool.request()
      .input("type", sql.VarChar, type)
      .query(`
        SELECT ReportID, Report_Location
        FROM Report
        WHERE emergencyType = @type
      `);

    const reports = result.recordset;
    const suburbCounts = {};
    const points = [];
    const seenCoords = new Map();

    for (const { Report_Location } of reports) {
      const [latStr, lngStr] = (Report_Location || "").split(";");
      const lat = parseFloat(latStr);
      const lng = parseFloat(lngStr);

      if (isNaN(lat) || isNaN(lng)) continue;

      points.push({ lat, lng, intensity: 1 });
      const coordKey = `${lat},${lng}`;

      if (!seenCoords.has(coordKey)) {
        try {
          const geoRes = await fetch(
            `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lng}&format=json&addressdetails=1&zoom=18`,
            { headers: { "User-Agent": "SizaCommunityWatch/1.0" } }
          );

          if (!geoRes.ok) throw new Error(`Geocoding error: ${geoRes.status}`);
          const geoData = await geoRes.json();
          const suburb = geoData?.address?.suburb || geoData?.address?.town || "Unknown Location";
          seenCoords.set(coordKey, suburb);
        } catch (err) {
          console.error('Geocoding fetch failed:', err);
          seenCoords.set(coordKey, "Unknown Location");
        }
      }

      const suburbName = seenCoords.get(coordKey);
      suburbCounts[suburbName] = (suburbCounts[suburbName] || 0) + 1;
    }

    const suburbArray = Object.entries(suburbCounts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);

    res.json({ success: true, heatData: points, suburbData: suburbArray });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});


app.get('/getReportsadmin', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request().query(`
      SELECT 
        ReportID,
        EmergencyType,
        EmerDescription,
        Report_Location,
        Report_Status,
        dateReported
      FROM Report
      WHERE CAST(dateReported AS DATE) = CAST(dbo.GetSASTDateTime() AS DATE)
    `);

    const reports = result.recordset;
    const count = reports.length;

    if (count === 0) {
      return res.status(200).json({
        success: true,
        message: 'No reports found for today.',
        count: 0,
        Reports: [],
      });
    }

    res.status(200).json({
      success: true,
      message: `${count} report(s) found for today.`,
      count,
      Reports: reports,
    });
  } catch (error) {
    console.error('SQL error', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch reports',
      error: error.message,
    });
  }
});
//******************NOTIFICATIONS ENDPOINTS ADMIN********************//
// Create notification content
const createNotification = async (type, entityType, entityId, title, message, metadata = null) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('NotificationType', sql.VarChar(50), type)
      .input('EntityType', sql.VarChar(50), entityType)
      .input('EntityID', sql.Int, entityId)
      .input('Title', sql.VarChar(255), title)
      .input('Message', sql.VarChar(sql.MAX), message)
      .input('Metadata', sql.VarChar(sql.MAX), metadata)
      .query(`
        INSERT INTO Notifications 
        (NotificationType, EntityType, EntityID, Title, Message, Metadata)
        OUTPUT INSERTED.NotificationID
        VALUES (@NotificationType, @EntityType, @EntityID, @Title, @Message, @Metadata)
      `);
    return result.recordset[0].NotificationID;
  } catch (err) {
    console.error('Error creating notification:', err);
    throw err;
  }
};

// Add recipients to notification
const addNotificationRecipients = async (notificationId, userIds) => {
  if (userIds.length === 0) return;

  try {
    const pool = await sql.connect(config);
    const request = pool.request();

    // Build dynamic query
    let query = `
      INSERT INTO NotificationRecipients (NotificationID, UserID, IsRead)
      VALUES 
    `;

    const values = [];
    userIds.forEach((userId, index) => {
      values.push(`(@NotificationID, @UserID${index}, 0)`);
      request.input(`UserID${index}`, sql.Int, userId);
    });

    query += values.join(',');
    request.input('NotificationID', sql.Int, notificationId);

    await request.query(query);
  } catch (err) {
    console.error('Error adding recipients:', err);
    throw err;
  }
};

// GET /api/Leader/notifications
app.get('/api/Leader/:userId/notifications', async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        SELECT 
          n.NotificationID,
          n.NotificationType,
          n.EntityType,
          n.EntityID,
          n.Title,
          n.Message,
          n.CreatedAt,
          n.Metadata,
          nr.IsRead,
          nr.ReadAt
        FROM NotificationRecipients nr
        JOIN Notifications n ON n.NotificationID = nr.NotificationID
        WHERE nr.UserID = @UserID
        ORDER BY n.CreatedAt DESC
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching notifications:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH /api/Leader/notifications/:id/read
app.patch('/api/Leader/notifications/:id/read', async (req, res) => {
  const notificationId = parseInt(req.params.id, 10);
  const userId = req.body.userId;

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  try {
    const pool = await sql.connect(config);
    await pool.request()
      .input('NotificationID', sql.Int, notificationId)
      .input('UserID', sql.Int, userId)
      .query(`
        UPDATE NotificationRecipients
        SET IsRead = 1, ReadAt = dbo.GetSASTDateTime()
        WHERE NotificationID = @NotificationID AND UserID = @UserID
      `);

    res.json({ success: true });
  } catch (err) {
    console.error('Error marking notification as read:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH /api/Leader/notifications/allread/:userId
app.patch('/api/Leader/notifications/allread/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId, 10)

  if (!userId || isNaN(Number(userId))) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('UserID', sql.Int, userId)
      .query(`
        UPDATE nr
        SET IsRead = 1, 
            ReadAt = dbo.GetSASTDateTime()
        FROM NotificationRecipients nr
        INNER JOIN Notifications n ON n.NotificationID = nr.NotificationID
        WHERE nr.UserID = @UserID
          AND n.NotificationType = 'BROADCAST'
          AND nr.IsRead = 0
      `);

    res.json({
      success: true,
      message: `Marked ${result.rowsAffected[0]} notifications as read`
    });
  } catch (err) {
    console.error('Error marking notifications as read:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add this GET endpoint for testing purposes only
app.get('/api/Leader/notifications/allread/:userId', (req, res) => {
  res.status(405).json({
    error: 'Method not allowed. Use PATCH instead.',
    example: `curl -X PATCH "https://your-api.com/api/Leader/notifications/allread/${req.params.userId}"`
  });
});

//******************STATISTICS ENDPOINTS ADMIN********************//

// Helper function to format dates for SQL Server
function getDateRange(timeFrame) {
  const now = new Date();
  const start = new Date(now);

  switch (timeFrame) {
    case 'day':
      start.setDate(now.getDate() - 1);
      break;
    case 'week':
      start.setDate(now.getDate() - 7);
      break;
    case 'month':
      start.setMonth(now.getMonth() - 1);
      break;
    case 'year':
      start.setFullYear(now.getFullYear() - 1);
      break;
    default:
      start.setMonth(now.getMonth() - 1);
  }

  // Format dates for SQL Server
  return {
    start: start.toISOString().slice(0, 19).replace('T', ' '),
    end: now.toISOString().slice(0, 19).replace('T', ' ')
  };
}

// Total Incidents Overview - FIXED VERSION
app.get('/api/analytics/overview', async (req, res) => {
  try {
    const { timeFrame = 'month' } = req.query;
    const { start, end } = getDateRange(timeFrame);

    const pool = await sql.connect(config);

    // Get total reported incidents in time frame
    const reportedQuery = `
      SELECT COUNT(*) AS count
      FROM Report
      WHERE dateReported BETWEEN '${start}' AND '${end}'
    `;

    // Get resolved incidents in time frame - using 'Resolved' status
    const resolvedQuery = `
      SELECT COUNT(*) AS count
      FROM Report
      WHERE dateReported BETWEEN '${start}' AND '${end}'
        AND Report_Status = 'Completed'
    `;

    const reportedRes = await pool.request().query(reportedQuery);
    const resolvedRes = await pool.request().query(resolvedQuery);

    const reported = reportedRes.recordset[0]?.count || 0;
    const resolved = resolvedRes.recordset[0]?.count || 0;
    const unresolved = reported - resolved;

    res.json({ reported, resolved, unresolved });
  } catch (err) {
    console.error('Error fetching overview data:', err);
    res.status(500).json({
      error: 'Internal server error',
      details: err.message
    });
  }
});


// Reports Over Time - FIXED VERSION
app.get('/api/analytics/time', async (req, res) => {
  try {
    const { timeFrame = 'month' } = req.query;
    const { start, end } = getDateRange(timeFrame);
    const pool = await sql.connect(config);

    let query = '';
    let labels = [];

    if (timeFrame === 'day') {
      // Group by hour
      query = `
        SELECT DATEPART(HOUR, dateReported) AS hour, COUNT(*) AS count
        FROM Report
        WHERE dateReported BETWEEN '${start}' AND '${end}'
        GROUP BY DATEPART(HOUR, dateReported)
        ORDER BY hour
      `;
      labels = Array.from({ length: 24 }, (_, i) => `${i}:00`);
    }
    else if (timeFrame === 'week') {
      // Group by day of week
      query = `
        SELECT DATEPART(WEEKDAY, dateReported) AS day, COUNT(*) AS count
        FROM Report
        WHERE dateReported BETWEEN '${start}' AND '${end}'
        GROUP BY DATEPART(WEEKDAY, dateReported)
        ORDER BY day
      `;
      labels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    }
    else if (timeFrame === 'month') {
      // Group by day of month
      query = `
        SELECT DAY(dateReported) AS day, COUNT(*) AS count
        FROM Report
        WHERE dateReported BETWEEN '${start}' AND '${end}'
        GROUP BY DAY(dateReported)
        ORDER BY day
      `;
      labels = Array.from({ length: 31 }, (_, i) => (i + 1).toString());
    }
    else { // year
      // Group by month
      query = `
        SELECT MONTH(dateReported) AS month, COUNT(*) AS count
        FROM Report
        WHERE dateReported BETWEEN '${start}' AND '${end}'
        GROUP BY MONTH(dateReported)
        ORDER BY month
      `;
      labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    }

    const result = await pool.request().query(query);

    // Create data array with zeros
    const data = labels.map(() => 0);

    // Fill with actual data
    result.recordset.forEach(row => {
      const index = timeFrame === 'day' ? row.hour :
        timeFrame === 'week' ? (row.day - 1) :
          timeFrame === 'month' ? (row.day - 1) :
            (row.month - 1);
      if (index >= 0 && index < data.length) {
        data[index] = row.count;
      }
    });

    res.json({ labels, data });
  } catch (err) {
    console.error('Error fetching time data:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reports by Type - FIXED VERSION
app.get('/api/analytics/type', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const query = `
      SELECT 
        CASE 
          WHEN emergencyType IN ('Crime', 'Medical', 'Fire', 'Natural disaster', 'SOS',  'Suspicious Activity') 
            THEN emergencyType
          ELSE 'Other'
        END AS type,
        COUNT(*) AS count
      FROM Report
      GROUP BY 
        CASE 
          WHEN emergencyType IN ('Crime', 'Medical', 'Fire', 'Natural disaster', 'SOS',  'Suspicious Activity') 
            THEN emergencyType
          ELSE 'Other'
        END
    `;

    const result = await pool.request().query(query);

    // Define required types in specific order
    const requiredTypes = ['Crime', 'Medical', 'Fire', 'Natural disaster', 'SOS', 'Suspicious Activity', 'Other'];
    const typeCounts = {};

    // Initialize with zeros
    requiredTypes.forEach(type => {
      typeCounts[type] = 0;
    });

    // Fill with actual counts
    result.recordset.forEach(row => {
      typeCounts[row.type] = row.count;
    });

    // Convert to arrays
    const labels = requiredTypes;
    const data = labels.map(type => typeCounts[type]);

    res.json({ labels, data });
  } catch (err) {
    console.error('Error fetching type data:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Top Responders Pie Chart
app.get('/api/analytics/top-responders', async (req, res) => {
  try {
    const { timeFrame = 'month' } = req.query;
    const { start, end } = getDateRange(timeFrame);
    const pool = await sql.connect(config);

    const query = `
      SELECT TOP 5 
        u.UserID,
        u.FullName,
        COUNT(r.ResponseID) AS responseCount
      FROM Response r
      JOIN Users u ON r.UserID = u.UserID
      JOIN Report rep ON r.reportID = rep.ReportID
      WHERE rep.dateReported BETWEEN '${start}' AND '${end}'
      GROUP BY u.UserID, u.FullName
      ORDER BY responseCount DESC
    `;

    const result = await pool.request().query(query);

    const labels = result.recordset.map(row => `${row.FullName} (ID: ${row.UserID})`);
    const data = result.recordset.map(row => row.responseCount);

    res.json({ labels, data });
  } catch (err) {
    console.error('Error fetching top responders:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Request Lifecycle Funnel
app.get('/api/analytics/funnel', async (req, res) => {
  try {
    const { timeFrame = 'month' } = req.query;
    const { start, end } = getDateRange(timeFrame);
    const pool = await sql.connect(config);

    const query = `
      SELECT 
        (SELECT COUNT(*) FROM Report 
         WHERE dateReported BETWEEN '${start}' AND '${end}') AS logged,
        
        (SELECT COUNT(DISTINCT r.reportID) FROM Response r
         JOIN Report rep ON r.reportID = rep.ReportID
         WHERE rep.dateReported BETWEEN '${start}' AND '${end}') AS accepted,
        
        (SELECT COUNT(*) FROM Report 
         WHERE Report_Status = 'Completed'
         AND dateReported BETWEEN '${start}' AND '${end}') AS resolved,
         
        (SELECT COUNT(*) FROM Report 
         WHERE Report_Status = 'Escalated'
         AND dateReported BETWEEN '${start}' AND '${end}') AS escalated,

         (SELECT COUNT(*) FROM Report 
         WHERE Report_Status = 'On-going'
         AND dateReported BETWEEN '${start}' AND '${end}') AS ongoing,

         (SELECT COUNT(*) FROM Report 
         WHERE Report_Status = 'Abandoned'
         AND dateReported BETWEEN '${start}' AND '${end}') AS abandoned,

         (SELECT COUNT(*) FROM Report 
         WHERE Report_Status = 'False report'
         AND dateReported BETWEEN '${start}' AND '${end}') AS falseReport
    `;

    const result = await pool.request().query(query);
    const row = result.recordset[0];

    res.json({
      logged: row.logged || 0,
      accepted: row.accepted || 0,
      resolved: row.resolved || 0,
      ongoing: row.ongoing || 0,
      abandoned: row.abandoned || 0,
      falseReport: row.falseReport || 0,
      escalated: row.escalated || 0
    });
  } catch (err) {
    console.error('Error fetching funnel data:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Broadcast Message Analytics
app.get('/api/analytics/messages', async (req, res) => {
  try {
    const { timeFrame = 'month' } = req.query;
    const { start, end } = getDateRange(timeFrame);
    const pool = await sql.connect(config);

    const query = `
      SELECT 
        (SELECT COUNT(*) FROM Messages 
         WHERE ChannelID = 1
         AND SentAt BETWEEN '${start}' AND '${end}') AS total,
        
        (SELECT COUNT(*) FROM Messages m
         LEFT JOIN FlaggedMessages fm ON m.MessageID = fm.MessageID
         WHERE m.ChannelID = 1
         AND m.SentAt BETWEEN '${start}' AND '${end}'
         AND fm.FlagID IS NULL) AS unflagged,
        
        (SELECT COUNT(DISTINCT fm.MessageID) 
         FROM FlaggedMessages fm
         JOIN Messages m ON fm.MessageID = m.MessageID
         WHERE m.ChannelID = 1
         AND m.SentAt BETWEEN '${start}' AND '${end}') AS flagged
    `;

    const result = await pool.request().query(query);
    const row = result.recordset[0];

    res.json({
      total: row.total || 0,
      unflagged: row.unflagged || 0,
      flagged: row.flagged || 0
    });
  } catch (err) {
    console.error('Error fetching message analytics:', err);
    res.status(500).json({
      error: 'Internal server error',
      details: err.message
    });
  }
});

/************************Voting Session ************************/

// server.js

// Get current voting settings
// Get current voting settings - FIXED to ensure we get the right active session
// Get current voting settings - FIXED date handling
app.get('/api/voting-settings', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    
    // First check if there's an active session
    const activeResult = await pool.request()
      .query(`
        SELECT TOP 1 * 
        FROM VotingSettings 
        WHERE VotingEnabled = 1 AND EndDate > dbo.GetSASTDateTime()
        ORDER BY SettingID DESC
      `);

    if (activeResult.recordset.length > 0) {
      const settings = activeResult.recordset[0];
      // Convert dates to ISO strings safely
      const formattedSettings = {
        ...settings,
        StartDate: settings.StartDate ? new Date(settings.StartDate).toISOString() : null,
        EndDate: settings.EndDate ? new Date(settings.EndDate).toISOString() : null,
        UpdatedAt: settings.UpdatedAt ? new Date(settings.UpdatedAt).toISOString() : null
      };
      return res.json(formattedSettings);
    }

    // If no active session, get the most recent one
    const latestResult = await pool.request()
      .query(`
        SELECT TOP 1 * 
        FROM VotingSettings 
        ORDER BY SettingID DESC
      `);

    if (latestResult.recordset.length > 0) {
      const settings = latestResult.recordset[0];
      const formattedSettings = {
        ...settings,
        StartDate: settings.StartDate ? new Date(settings.StartDate).toISOString() : null,
        EndDate: settings.EndDate ? new Date(settings.EndDate).toISOString() : null,
        UpdatedAt: settings.UpdatedAt ? new Date(settings.UpdatedAt).toISOString() : null
      };
      res.json(formattedSettings);
    } else {
      // Return default settings if none exist
      const defaultSettings = {
        VotingEnabled: false,
        StartDate: new Date().toISOString(),
        EndDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        SettingID: 0
      };
      res.json(defaultSettings);
    }
  } catch (err) {
    console.error('Error fetching voting settings:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update voting settings - IMPROVED with session validation
// Update voting settings - FIXED date handling
app.put('/api/voting-settings/update', async (req, res) => {
  const { VotingEnabled, StartDate, EndDate, UpdatedBy } = req.body;

  try {
    const pool = await sql.connect(config);
    
    // Check if there's already an active session
    const activeSessionCheck = await pool.request().query(`
      SELECT TOP 1 SettingID, VotingEnabled, EndDate 
      FROM VotingSettings 
      WHERE VotingEnabled = 1 AND EndDate > dbo.GetSASTDateTime()
      ORDER BY SettingID DESC
    `);

    // If trying to enable voting but there's already an active session
    if (VotingEnabled && activeSessionCheck.recordset.length > 0) {
      return res.status(400).json({ 
        error: 'There is already an active voting session. Please end the current session first.' 
      });
    }

    // Convert dates to proper format
    const startDateObj = new Date(StartDate);
    const endDateObj = new Date(EndDate);

    await pool.request()
      .input('VotingEnabled', sql.Bit, VotingEnabled)
      .input('StartDate', sql.DateTime, startDateObj)
      .input('EndDate', sql.DateTime, endDateObj)
      .input('UpdatedBy', sql.Int, UpdatedBy)
      .query(`
        -- Check if a setting exists
        DECLARE @currentSettingID INT;
        SELECT TOP 1 @currentSettingID = SettingID 
        FROM VotingSettings 
        ORDER BY SettingID DESC;
        
        IF @currentSettingID IS NOT NULL
        BEGIN
            UPDATE VotingSettings SET
              VotingEnabled = @VotingEnabled,
              StartDate = @StartDate,
              EndDate = @EndDate,
              UpdatedBy = @UpdatedBy,
              UpdatedAt = dbo.GetSASTDateTime()
            WHERE SettingID = @currentSettingID
        END
        ELSE
        BEGIN
            INSERT INTO VotingSettings (
              VotingEnabled, 
              StartDate, 
              EndDate, 
              UpdatedBy,
              UpdatedAt
            ) VALUES (
              @VotingEnabled,
              @StartDate,
              @EndDate,
              @UpdatedBy,
              dbo.GetSASTDateTime()
            )
        END
      `);

    res.json({ success: true });
  } catch (err) {
    console.error('Error updating voting settings:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start a new voting session - creates new SettingID for fresh nominations/votes
// Start a new voting session - FIXED date handling
app.post('/api/voting-settings/new-session', async (req, res) => {
  const { StartDate, EndDate, UpdatedBy } = req.body;

  try {
    const pool = await sql.connect(config);
    
    // Check if there are any active sessions
    const activeSessionCheck = await pool.request().query(`
      SELECT TOP 1 SettingID 
      FROM VotingSettings 
      WHERE VotingEnabled = 1 AND EndDate > dbo.GetSASTDateTime()
    `);

    if (activeSessionCheck.recordset.length > 0) {
      return res.status(400).json({ 
        error: 'Cannot start new session while there is an active voting session.' 
      });
    }

    // Convert dates to proper format
    const startDateObj = new Date(StartDate);
    const endDateObj = new Date(EndDate);

    // Create new session
    const result = await pool.request()
      .input('StartDate', sql.DateTime, startDateObj)
      .input('EndDate', sql.DateTime, endDateObj)
      .input('UpdatedBy', sql.Int, UpdatedBy)
      .query(`
        INSERT INTO VotingSettings (
          VotingEnabled, 
          StartDate, 
          EndDate, 
          UpdatedBy,
          UpdatedAt
        ) VALUES (
          1, -- Enable voting for new session
          @StartDate,
          @EndDate,
          @UpdatedBy,
          dbo.GetSASTDateTime()
        )
        
        SELECT SCOPE_IDENTITY() AS NewSettingID;
      `);

    const newSettingID = result.recordset[0].NewSettingID;
    
    res.json({ 
      success: true, 
      message: 'New voting session started successfully',
      newSettingID 
    });
  } catch (err) {
    console.error('Error starting new voting session:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Promote a user to Community Leader
app.put('/api/community-members/:userId/promote', async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        UPDATE CommunityMember
        SET Role = 'CommunityLeader'
        WHERE UserID = @userId
        
        IF @@ROWCOUNT = 0
        BEGIN
          -- Create a new record if one doesn't exist
          INSERT INTO CommunityMember (UserID, Role)
          VALUES (@userId, 'CommunityLeader')
        END
        
        SELECT * FROM CommunityMember WHERE UserID = @userId
      `);

    if (result.recordset.length > 0) {
      res.json({
        success: true,
        message: 'User promoted to Community Leader',
        user: result.recordset[0]
      });
    } else {
      res.status(404).json({ error: 'User not found in community members' });
    }
  } catch (err) {
    console.error('Error promoting user:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Promote top 3 nominees as Community Leaders - WITH VOTE REQUIREMENT
app.post('/api/voting-settings/promote-top3', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    
    // Get top 3 nominees by votes for the latest session
    const topNominees = await pool.request().query(`
      SELECT TOP 3 n.NomineeID, COUNT(v.VoteID) AS VoteCount
      FROM Nominations n
      LEFT JOIN Votes v ON n.NominationID = v.NomineeID
      WHERE n.SettingID = (SELECT TOP 1 SettingID FROM VotingSettings ORDER BY SettingID DESC)
      GROUP BY n.NomineeID
      HAVING COUNT(v.VoteID) > 0  -- Only include nominees with at least 1 vote
      ORDER BY COUNT(v.VoteID) DESC
    `);

    if (topNominees.recordset.length === 0) {
      return res.status(400).json({ 
        error: 'No eligible nominees found to promote. At least one nominee must have votes.' 
      });
    }

    // Ensure we have at least the top nominee (required), others are optional
    const requiredNominees = topNominees.recordset.slice(0, 1); // Top 1 is required
    const optionalNominees = topNominees.recordset.slice(1, 3); // Next 2 are optional

    const promotionResults = [];
    
    // Promote required top nominee (must have votes)
    for (const nominee of requiredNominees) {
      const result = await pool.request()
        .input('userId', sql.Int, nominee.NomineeID)
        .query(`
          UPDATE CommunityMember
          SET Role = 'CommunityLeader'
          WHERE UserID = @userId
          
          IF @@ROWCOUNT = 0
          BEGIN
            INSERT INTO CommunityMember (UserID, Role)
            VALUES (@userId, 'CommunityLeader')
          END
        `);

      promotionResults.push({
        nomineeId: nominee.NomineeID,
        voteCount: nominee.VoteCount,
        position: 1,
        promoted: true
      });
    }

    // Promote optional nominees (if they exist and have votes)
    for (const nominee of optionalNominees) {
      const result = await pool.request()
        .input('userId', sql.Int, nominee.NomineeID)
        .query(`
          UPDATE CommunityMember
          SET Role = 'CommunityLeader'
          WHERE UserID = @userId
          
          IF @@ROWCOUNT = 0
          BEGIN
            INSERT INTO CommunityMember (UserID, Role)
            VALUES (@userId, 'CommunityLeader')
          END
        `);

      promotionResults.push({
        nomineeId: nominee.NomineeID,
        voteCount: nominee.VoteCount,
        position: promotionResults.length + 1,
        promoted: true
      });
    }

    res.json({
      success: true,
      message: `Successfully promoted ${promotionResults.length} user(s) to Community Leaders`,
      results: promotionResults,
      note: promotionResults.length === 1 
        ? 'Only the top nominee was promoted (minimum requirement met)'
        : `Top ${promotionResults.length} nominees promoted`
    });
  } catch (err) {
    console.error('Error promoting top 3:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to check and disable expired voting sessions - FIXED
app.put('/api/voting-settings/check-expiry', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    // 1. Get current SAST time from database function
    const currentTimeResult = await pool.request().query('SELECT dbo.GetSASTDateTime() AS CurrentTime');
    const currentTime = currentTimeResult.recordset[0].CurrentTime;

    // 2. Check for active sessions that have ended - USING PARAMETERIZED QUERY
    const result = await pool.request()
      .input('currentTime', sql.DateTime, currentTime)
      .query(`
        UPDATE VotingSettings
        SET VotingEnabled = 0
        WHERE SettingID = (
          SELECT TOP 1 SettingID 
          FROM VotingSettings 
          WHERE VotingEnabled = 1 
            AND EndDate < @currentTime
          ORDER BY SettingID DESC
        )
        
        SELECT @@ROWCOUNT AS UpdatedCount
      `);

    const updatedCount = result.recordset[0].UpdatedCount;

    if (updatedCount > 0) {
      res.json({
        success: true,
        message: 'Disabled expired voting session',
        updatedCount
      });
    } else {
      res.json({
        success: true,
        message: 'No active sessions to expire',
        updatedCount: 0
      });
    }
  } catch (err) {
    console.error('Error checking voting expiry:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check if voting session has ended - FIXED
app.get('/api/voting-settings/has-ended', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    // Get current SAST time from database function
    const currentTimeResult = await pool.request().query('SELECT dbo.GetSASTDateTime() AS CurrentTime');
    const currentTime = currentTimeResult.recordset[0].CurrentTime;

    // Get the latest voting settings
    const settingsResult = await pool.request().query(`
      SELECT TOP 1 EndDate 
      FROM VotingSettings 
      ORDER BY SettingID DESC
    `);

    if (settingsResult.recordset.length === 0) {
      return res.json({ hasEnded: false });
    }

    const endDate = settingsResult.recordset[0].EndDate;
    
    // Compare dates directly from database (no string conversion issues)
    const hasEnded = currentTime > endDate;

    res.json({ hasEnded });
  } catch (err) {
    console.error('Error checking session end:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all nominations with vote counts - FIXED
app.get('/api/nominations', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.request().query(`
      SELECT 
        n.*,
        COALESCE(v.VoteCount, 0) AS VoteCount
      FROM Nominations n
      LEFT JOIN (
        SELECT n.NomineeID, COUNT(*) AS VoteCount
        FROM Votes v
        INNER JOIN Nominations n ON v.NomineeID = n.NominationID
        WHERE n.SettingID = (
          SELECT TOP 1 SettingID 
          FROM VotingSettings 
          ORDER BY SettingID DESC
        )
        GROUP BY n.NomineeID
      ) v ON n.NomineeID = v.NomineeID
      WHERE n.SettingID = (
        SELECT TOP 1 SettingID 
        FROM VotingSettings 
        ORDER BY SettingID DESC
      )
      ORDER BY n.NominatedAt DESC
    `);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching nominations:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/// Get all votes for CURRENT session
// Get all votes for CURRENT session - FIXED
app.get('/api/votes', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.request().query(`
      SELECT 
        v.VoteID,
        v.VoterID,
        v.NomineeID AS NominationID,  -- This is actually the NominationID
        n.NomineeID AS NomineeUserID, -- This is the actual user who was nominated
        v.VotedAt
      FROM Votes v
      INNER JOIN Nominations n ON v.NomineeID = n.NominationID
      WHERE n.SettingID = (
        SELECT TOP 1 SettingID 
        FROM VotingSettings 
        ORDER BY SettingID DESC
      )
      ORDER BY v.VotedAt DESC
    `);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching votes:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get users (simplified version)
app.get('/api/users-minimal', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.request().query(`
      SELECT UserID, FullName, Email, ProfilePhoto 
      FROM Users
    `);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get vote counts by nominee
// Get vote counts by nominee - FIXED
app.get('/api/votes/count', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.request().query(`
      SELECT 
        n.NomineeID AS NomineeUserID,  -- Count by the actual user, not nomination
        COUNT(*) AS VoteCount
      FROM Votes v
      INNER JOIN Nominations n ON v.NomineeID = n.NominationID
      WHERE n.SettingID = (
        SELECT TOP 1 SettingID 
        FROM VotingSettings 
        ORDER BY SettingID DESC
      )
      GROUP BY n.NomineeID
    `);

    const counts = {};
    result.recordset.forEach(row => {
      const nomineeUserId = parseInt(row.NomineeUserID, 10);
      counts[nomineeUserId] = row.VoteCount;
    });

    res.json(counts);
  } catch (err) {
    console.error('Error fetching vote counts:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check if user is in top 3 by votes
app.get('/api/voting-settings/is-top3/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  try {
    const pool = await sql.connect(config);
    
    // Get top 3 nominees with votes for current session
    const result = await pool.request().query(`
      SELECT TOP 3 n.NomineeID, COUNT(v.VoteID) AS VoteCount
      FROM Nominations n
      LEFT JOIN Votes v ON n.NominationID = v.NomineeID
      WHERE n.SettingID = (
        SELECT TOP 1 SettingID 
        FROM VotingSettings 
        ORDER BY SettingID DESC
      )
      GROUP BY n.NomineeID
      HAVING COUNT(v.VoteID) > 0  -- Only include nominees with at least 1 vote
      ORDER BY COUNT(v.VoteID) DESC
    `);

    // Extract just the user IDs from top 3
    const top3UserIds = result.recordset.map(row => row.NomineeID);
    
    // Check if the requested user is in top 3
    const isInTop3 = top3UserIds.includes(userId);

    res.json({ 
      isInTop3,
      top3UserIds,
      position: isInTop3 ? top3UserIds.indexOf(userId) + 1 : null
    });
  } catch (err) {
    console.error('Error checking top 3 status:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/****************SUPPORT PAGE  *********************/
// Support Dashboard API Endpoints

// Get all support items (misuse reports and flagged messages)
// server.js
app.get('/api/support/items', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    // Get misuse reports with filer count
    const misuseQuery = `
      SELECT 
        mr.MisuseID AS id,
        'misuse' AS type,
        mr.MisuseStatus AS status,
        CONVERT(varchar, mr.CreatedAt, 126) AS createdAt, 
        r.ReporterID AS reporterId,
        u.FullName AS reporterName,
        mr.ReportID AS reportId,
        mr.InitialDescription AS description,
        mr.MisuseType AS reason,
        COUNT(mf.FilerID) AS filerCount
      FROM MisuseReport mr
      INNER JOIN Report r ON mr.ReportID = r.ReportID
      INNER JOIN Users u ON r.ReporterID = u.UserID
      LEFT JOIN MisuseFiler mf ON mr.MisuseID = mf.MisuseID
      GROUP BY 
        mr.MisuseID, mr.MisuseStatus, mr.CreatedAt, r.ReporterID, 
        u.FullName, mr.ReportID, mr.InitialDescription, mr.MisuseType
    `;

    // Get flagged messages
    // server.js - Flagged Messages Query
    const flaggedQuery = `
  SELECT 
    fm.FlagID AS id,
    'flagged' AS type,
    fm.FlaggedStatus AS status,
    CONVERT(varchar, fm.FlaggedAt, 126) AS createdAt,
    fm.UserID AS reporterId,
    u.FullName AS reporterName,
    m.MessageID AS messageId,
    m.Content AS messageContent,
    fm.Reason AS reason 
  FROM FlaggedMessages fm
  INNER JOIN Messages m ON fm.MessageID = m.MessageID
  INNER JOIN Users u ON fm.UserID = u.UserID
`;

    const misuseResult = await pool.request().query(misuseQuery);
    const flaggedResult = await pool.request().query(flaggedQuery);

    // Combine results
    const items = [
      ...misuseResult.recordset,
      ...flaggedResult.recordset
    ].map(item => ({
      ...item,
      filerCount: item.filerCount ? parseInt(item.filerCount) : 0,
      // Ensure createdAt is always in ISO format
      createdAt: item.createdAt || null
    }));

    res.json(items);
  } catch (err) {
    console.error('Error fetching support items:', err);
    res.status(500).json({
      error: 'Internal server error',
      details: err.message
    });
  }
});

// Get filers for a misuse report
app.get('/api/support/misuse/filers/:misuseId', async (req, res) => {
  const misuseId = parseInt(req.params.misuseId, 10);

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('misuseId', sql.Int, misuseId)
      .query(`
        SELECT 
          u.UserID AS id,
          u.FullName AS name,
          u.Email,
          mf.FiledAt,
          mf.AdditionalDescription
        FROM MisuseFiler mf
        INNER JOIN Response r ON mf.ResponseID = r.ResponseID
        INNER JOIN Users u ON r.UserID = u.UserID
        WHERE mf.MisuseID = @misuseId
        ORDER BY mf.FiledAt DESC
      `);

    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching misuse filers:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update item status
app.put('/api/support/items/:type/:id/status', async (req, res) => {
  const { type, id } = req.params;
  const { status } = req.body;

  if (!['misuse', 'flagged'].includes(type)) {
    return res.status(400).json({ error: 'Invalid item type' });
  }

  if (!['Pending', 'Reviewed', 'Resolved'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  try {
    const pool = await sql.connect(config);

    if (type === 'misuse') {
      await pool.request()
        .input('id', sql.Int, id)
        .input('status', sql.VarChar(20), status)
        .query(`
          UPDATE MisuseReport 
          SET MisuseStatus = @status 
          WHERE MisuseID = @id
        `);
    } else {
      await pool.request()
        .input('id', sql.Int, id)
        .input('status', sql.VarChar(20), status)
        .query(`
          UPDATE FlaggedMessages 
          SET FlaggedStatus = @status 
          WHERE FlagID = @id
        `);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Error updating item status:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get support statistics
app.get('/api/support/stats', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const misusePending = await pool.request().query(`
      SELECT COUNT(*) AS count 
      FROM MisuseReport 
      WHERE MisuseStatus = 'Pending'
    `);

    const flaggedPending = await pool.request().query(`
      SELECT COUNT(*) AS count 
      FROM FlaggedMessages 
      WHERE FlaggedStatus = 'Pending'
    `);

    const stats = {
      totalPending: misusePending.recordset[0].count + flaggedPending.recordset[0].count,
      misusePending: misusePending.recordset[0].count,
      flaggedPending: flaggedPending.recordset[0].count
    };

    res.json(stats);
  } catch (err) {
    console.error('Error fetching support stats:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/getDatesByEmergencyType', async (req, res) => {
  const { emergencyType } = req.query; // expects ?emergencyType=Fire

  try {
    const pool = await sql.connect(config);

    if (!emergencyType) {
      return res.status(400).json({ message: "Missing emergencyType in query." });
    }

    const result = await pool.request()
      .input('emergencyType', sql.VarChar, emergencyType)
      .query(`
        SELECT dateReported, suburbName
        FROM [dbo].[Report]
        WHERE emergencyType = @emergencyType
      `);

    res.status(200).json({
      success: true,
      emergencyType,
      data: result.recordset // now each record has { dateReported, suburbName }
    });

  } catch (err) {
    console.error("Error fetching dates:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

