const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const fetch = require('node-fetch');
const { connect } = require('http2');

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


// SQL Server Configuration
const config = {
  server: process.env.DB_SERVER || 'siza-server-123.database.windows.net',
  user: process.env.DB_USER || 'sizaadmin',
  password: process.env.DB_PASSWORD || 'YourPassword123!',
  database: 'SIZA',
  options: { encrypt: true }
};


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

// Registration Endpoint
app.post('/register', async (req, res) => {
  const { fullName, email, password, phoneNumber, role, dob, homeAddress, imageBase64, gender } = req.body;
  const Username = email.split("@")[0];
  const userType = 'CommunityMember';
  console.log('data: ', req.body);


  try {
    const pool = await sql.connect(config);
    //insert user first
    const usersResult = await pool.request()
      .input('FullName', sql.VarChar, fullName)
      .input('Email', sql.VarChar, email)
      .input('Username', sql.VarChar, Username)
      .input('PhoneNumber', sql.VarChar, phoneNumber)
      .input('Passcode', sql.VarChar, password)
      .input('UserType', sql.VarChar, userType)
      .input('CreatedAt', sql.DateTime, new Date())
      .input('ProfilePhoto', sql.VarChar, imageBase64)
      .input('AcceptedTerms', sql.VarChar, 'No')
      .input('Gender', sql.VarChar, gender)
      .query(`
           INSERT INTO [dbo].[Users]
           (FullName, Email, Username, PhoneNumber, Passcode, UserType, CreatedAt, ProfilePhoto, AcceptedTerms, Gender)
           OUTPUT INSERTED.UserID
           VALUES
           (@FullName, @Email, @Username, @PhoneNumber, @Passcode, @UserType, @CreatedAt, @ProfilePhoto, @AcceptedTerms, @Gender)
            `);

    const userID = usersResult.recordset[0].UserID;
    if (userType === 'CommunityMember') {
      await pool.request()
        .input('UserID', sql.BigInt, userID)
        .input('Role', sql.VarChar, role)
        .input('DOB', sql.Date, dob)
        .input('HomeAddress', sql.VarChar, homeAddress)
        .input('TrustedContacts', sql.VarChar, '0')
        .query(`
                    INSERT INTO [dbo].[CommunityMember]
                    (UserID, Role, DOB, HomeAddress, TrustedContacts)
                    VALUES
                    (@UserID, @Role, @DOB, @HomeAddress, @TrustedContacts) 
                    `);
    }
    res.status(201).json({ message: 'User registered successfully.' });
  }
  catch (err) {
    console.error('Registration error:', err);
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


app.post('/addReport', async (req, res) => {
  const { reporterID, emergencyType, emerDescription, mediaPhoto, mediaVoice, sharedWith, reportLocation, reportStatus } = req.body;

  try {
    const pool = await sql.connect(config);

    // Assign the query result to `result`
    const result = await pool.request()
      .input('ReporterID', sql.Int, reporterID)
      .input('EmergencyType', sql.VarChar, emergencyType)
      .input('EmerDescription', sql.VarChar, emerDescription)
      .input('MediaPhoto', sql.VarChar, mediaPhoto)
      .input('MediaVoice', sql.VarChar, mediaVoice)
      .input('SharedWith', sql.VarChar, sharedWith)
      .input('ReportLocation', sql.VarChar, reportLocation)
      .input('ReportStatus', sql.VarChar, reportStatus)
      .query(`
                INSERT INTO [dbo].[Report]
                (ReporterID, emergencyType, emerDescription, media_Photo, media_Voice, sharedWith, Report_Location, Report_Status, dateReported)
                OUTPUT INSERTED.ReportID
                VALUES
                (@ReporterID, @EmergencyType, @EmerDescription, @MediaPhoto, @MediaVoice, @SharedWith, @ReportLocation, @ReportStatus,GETDATE())
            `);

    const insertedReportID = result.recordset[0].ReportID;

    res.status(201).json({
      message: 'Report submitted successfully.',
      reportID: insertedReportID
    });
  } catch (err) {
    console.error('Add report error:', err);
    res.status(500).json({ message: 'Internal server error.' });
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
  const { userIds, notiTitle, msg, readStatus, reportid, reporterID } = req.body;
  //console.log('Received user data: ', req.body);

  const tokens = userIds.split(' ');
  const insertedNotificationIDs = [];

  try {
    const pool = await sql.connect(config);

    for (let i = 0; i < tokens.length; i++) {
      const userId = parseInt(tokens[i]);
      if (parseInt(reporterID) === userId) continue;
      if (!isNaN(userId)) {
        const result = await pool.request()
          .input('notiTitle', sql.VarChar, notiTitle)
          .input('msg', sql.VarChar, msg)
          .input('readStatus', sql.VarChar, readStatus)
          .input('createdDate', sql.DateTime, new Date())
          .input('userId', sql.BigInt, userId)
          .input('reportID', sql.BigInt, reportid)
          .query(`
                        INSERT INTO [dbo].[Notification]
                        (notiTitle, msg, readStatus, createdDate, reportID, userId)
                        OUTPUT INSERTED.notificationID
                        VALUES
                        (@notiTitle, @msg, @readStatus, @createdDate, @reportID, @userId)
                    `);

        console.log("Notification added for UserID", userId, "-> ID:", result.recordset[0].notificationID);
        insertedNotificationIDs.push(result.recordset[0].notificationID);
      }
    }

    res.status(201).json({
      success: true,
      insertedNotificationIDs
    });
  } catch (err) {
    console.error('Error submitting notification:', err);
    res.status(500).json({ success: false, message: 'Internal server error.' });
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
        INSERT INTO Response (UserID, res_Location, res_Status, reportID)
        OUTPUT INSERTED.ResponseID
        VALUES (@UserID, @res_Location, @res_Status, @reportID)
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
      .input('timeSent', sql.DateTime, new Date())
      .input('msg', sql.VarChar(sql.MAX), msg) // use max length for msg
      .query(`
                INSERT INTO [dbo].[chatMessage] 
                (reporterID, responderID, reportID, timeSent, msg)
                OUTPUT INSERTED.msgID
                VALUES (@reporterID, @responderID, @reportID, @timeSent, @msg)
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
                VALUES (@MessageID, @UserID, GETDATE())
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

    // Insert with current timestamp
    await pool.request()
      .input('MessageID', sql.Int, messageId)
      .input('UserID', sql.Int, userId)
      .query(`
                INSERT INTO MessageReadStatus (MessageID, UserID, ReadAt)
                VALUES (@MessageID, @UserID, GETDATE())
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
        WHERE m.MessageID > @LastMessageID AND m.ChannelID = @ChannelID
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
                VALUES (@MessageID, @UserID, GETDATE())
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
        SET Status = @Status, RespondedAt = GETDATE()
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
        SET Status = @Status, RespondedAt = GETDATE()
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
        VALUES (@userID, @msg, @reportID, GETDATE())
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
      .input('CreatedAt', sql.DateTime, new Date())
      .input('ProfilePhoto', sql.VarChar, imageBase64)
      .input('AcceptedTerms', sql.VarChar, acceptedTerms)
      .query(`
        INSERT INTO [dbo].[Users]
        (FullName, Email, Username, PhoneNumber, Passcode, UserType, CreatedAt, ProfilePhoto, AcceptedTerms)
        OUTPUT INSERTED.UserID
        VALUES
        (@FullName, @Email, @Username, @PhoneNumber, @Passcode, @UserType, @CreatedAt, @ProfilePhoto, @AcceptedTerms)
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
        WHERE Email = @Email AND (UserType = 'admin'  OR UserType = 'CommunityMember')
      `);

    if (userResult.recordset.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const user = userResult.recordset[0];


    if (user.UserType === "CommunityMember") {
      const communityResult = await pool.request()
        .input('UserID', sql.Int, user.UserID)
        .query(`
                SELECT Role, DOB, HomeAddress, TrustedContacts
                FROM [dbo].[CommunityMember]
                WHERE UserID = @UserID
            `);

      const role = communityResult.recordset.length > 0
        ? communityResult.recordset[0].Role
        : 'Volunteer';

      const communitym = communityResult.recordset[0];

      // Return properly structured response
      res.json({
        success: true,
        user: {
          UserID: user.UserID,
          FullName: user.FullName,
          Email: user.Email,
          Username: user.Username,
          PhoneNumber: user.PhoneNumber,
          UserType: user.UserType,
          CreatedAt: user.CreatedAt,
          ProfilePhoto: user.ProfilePhoto, // Fixed typo (was 'profile')
          Role: role,
          DOB: communitym.DOB,
          HomeAddress: communitym.HomeAddress,
          TrustedContacts: communitym.TrustedContacts,
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

      // Return properly structured response
      res.json({
        success: true,
        user: {
          UserID: user.UserID,
          FullName: user.FullName,
          Email: user.Email,
          Username: user.Username,
          PhoneNumber: user.PhoneNumber,
          UserType: user.UserType,
          CreatedAt: user.CreatedAt,
          ProfilePhoto: user.ProfilePhoto, // Fixed typo (was 'profile')
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

    // Verify old password
    const isValid = await bcrypt.compare(oldPassword, currentPassword);
    if (!isValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const newHash = await bcrypt.hash(newPassword, 10);

    // Update password
    await pool.request()
      .input('UserID', sql.Int, userId)
      .input('NewHash', sql.VarChar, newHash)
      .query('UPDATE Users SET Passcode = @NewHash WHERE UserID = @UserID');

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
      .input('Images64', sql.NVarChar(sql.MAX), imagesString) // Add images64 input
      .query(`
        INSERT INTO Messages (ChannelID, SenderID, Content, images64, SentAt)
        OUTPUT INSERTED.MessageID, INSERTED.SentAt, INSERTED.images64
        VALUES (@ChannelID, @SenderID, @Content, @Images64, GETDATE())
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

    const newMessage = {
      MessageID: result.recordset[0].MessageID,
      SenderID: senderId,
      SenderName: senderResult.recordset[0].FullName,
      Content: content,
      images64: imagesArray, // Array of base64 strings (empty if no images)
      SentAt: new Date(result.recordset[0].SentAt).toISOString()
    };

    res.status(201).json(newMessage);
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

// Mark all messages as read
app.post('/api/messages/:UserID/mark-all-read', async (req, res) => {
  const userId = parseInt(req.params.UserID, 10);
  const channelId = 1; // Melville Emergency Channel

  if (isNaN(UserID)) {
    return res.status(400).json({ error: 'Invalid channelId' });
  }

  try {
    const pool = await sql.connect(config);

    await pool.request()
      .input('UserID', sql.Int, userId)
      .input('ChannelID', sql.Int, channelId)
      .query(`
        INSERT INTO MessageReadStatus (MessageID, UserID, ReadAt)
        SELECT m.MessageID, @UserID, GETDATE()
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

  if (isNaN(UserID)) {
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
                VALUES (@MessageID, @UserID, GETDATE())
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

  if (isNaN(UserID)) {
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


//******************Manage users ENDPOINTS ADMIN********************//

// Get all volunteers (community members with role "Volunteer")
app.get('/api/volunteers', async (req, res) => {
  try {
    const pool = await sql.connect(config);

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
            AND (Duration IS NULL OR Duration > GETDATE())
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

// New endpoint to get flag counts
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

// Put a user to sleep
app.post('/api/sleep', async (req, res) => {
  const { userId, durationHours } = req.body;

  if (!userId || !durationHours) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const pool = await sql.connect(config);

    // Calculate end time
    const durationMinutes = durationHours * 60;
    const endTime = new Date();
    endTime.setMinutes(endTime.getMinutes() + durationMinutes);

    await pool.request()
      .input('UserID', sql.Int, userId)
      .input('OnBreak', sql.VarChar, 'Yes')
      .input('Duration', sql.DateTime, endTime)
      .query(`
        INSERT INTO Sleep (UserID, OnBreak, Duration)
        VALUES (@UserID, @OnBreak, @Duration)
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

app.get('/community/count', async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .query(`SELECT COUNT(*) AS MemberCount FROM [dbo].[CommunityMember]`);

    const count = result.recordset[0].MemberCount;

    res.status(200).json({
      success: true,
      message: 'Community member count retrieved successfully.',
      count: count
    });

  } catch (err) {
    console.error('Error counting community members:', err);
    res.status(500).json({
      success: false,
      message: 'Internal server error.'
    });
  }
});
//get crime report
app.get('/getCrimeReport', async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const result = await pool.query(`
      SELECT * FROM [dbo].[Report]
      WHERE emergencyType = 'Crime'
    `);

    // Return list of crime reports as 'Reports' array
    res.status(200).json({ success: true, Reports: result.recordset });
  } catch (err) {
    console.error('SQL ERROR', err);
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
      WHERE CAST(dateReported AS DATE) = CAST(GETDATE() AS DATE)
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


//******************STATISTICS ENDPOINTS ADMIN********************//

// Helper function to format dates for SQL Server
function getDateRange(timeFrame) {
  const now = new Date();
  const start = new Date(now);
  
  switch(timeFrame) {
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
          WHEN emergencyType IN ('Crime', 'Medical', 'Fire', 'Natural Disaster') 
            THEN emergencyType
          ELSE 'Other'
        END AS type,
        COUNT(*) AS count
      FROM Report
      GROUP BY 
        CASE 
          WHEN emergencyType IN ('Crime', 'Medical', 'Fire', 'Natural Disaster') 
            THEN emergencyType
          ELSE 'Other'
        END
    `;
    
    const result = await pool.request().query(query);
    
    // Define required types in specific order
    const requiredTypes = ['Crime', 'Medical', 'Fire', 'Natural Disaster', 'Other'];
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