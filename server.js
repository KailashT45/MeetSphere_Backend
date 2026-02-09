require('dotenv').config();

const express = require('express');
const app = express();
const server = require('http').createServer(app);
const cors = require('cors');
const axios = require('axios');
const io = require('socket.io')(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true
  }
});
const admin = require('firebase-admin');

// Initialize Firebase Admin
if (!admin.apps.length) {
  const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT 
    ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
    : require('./serviceAccountKey.json');

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();
const PORT = process.env.PORT || 5000;

// Store active meetings and sessions
const meetings = {};
const activeSessions = {};

// Rate limiting for AI API
const aiRateLimits = new Map();
const AI_RATE_LIMIT = 5000; // 5 seconds between requests per user

// Middleware
app.use(express.json());
app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true,
  methods: ["GET", "POST"]
}));

// Middleware to verify Firebase token for REST endpoints
const verifyAuthMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.userId = decodedToken.uid;
    req.userEmail = decodedToken.email;
    next();
  } catch (error) {
    console.error('Auth verification failed:', error);
    return res.status(401).json({ error: 'Invalid authentication token' });
  }
};

// Middleware to verify Firebase token for Socket.IO
const verifyAuth = async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const email = socket.handshake.auth.email;
    const displayName = socket.handshake.auth.displayName;

    if (!token || !email) {
      return next(new Error('Authentication required'));
    }

    try {
      const userRecord = await admin.auth().getUser(token);
      socket.userId = userRecord.uid;
      socket.userEmail = userRecord.email;
      socket.displayName = displayName || userRecord.displayName || userRecord.email;

      activeSessions[userRecord.uid] = {
        socketId: socket.id,
        email: userRecord.email,
        displayName: socket.displayName,
        connectedAt: new Date()
      };

      console.log(`✅ User authenticated: ${socket.displayName} (${socket.userEmail})`);
      next();
    } catch (error) {
      console.error('Auth verification failed:', error);
      return next(new Error('Invalid authentication token'));
    }
  } catch (error) {
    console.error('Authentication error:', error);
    return next(new Error('Authentication failed'));
  }
};

// Apply authentication middleware to Socket.IO
io.use(verifyAuth);

// Socket.IO event handlers
io.on('connection', (socket) => {
  console.log('User connected:', socket.id, '-', socket.displayName);

  // Join meeting
  socket.on('join-meeting', async ({ meetingId, userName }) => {
    try {
      if (!socket.userId) {
        socket.emit('auth-error', 'You must be logged in to join a meeting');
        return;
      }

      socket.join(meetingId);

      if (!meetings[meetingId]) {
        meetings[meetingId] = {
          createdBy: socket.userId,
          createdAt: new Date(),
          participants: []
        };
      }

      const participant = {
        id: socket.id,
        userId: socket.userId,
        name: userName || socket.displayName,
        email: socket.userEmail,
        joinedAt: new Date()
      };

      meetings[meetingId].participants.push(participant);

      await db.collection('meetings').doc(meetingId).set({
        createdBy: meetings[meetingId].createdBy,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        lastActive: admin.firestore.FieldValue.serverTimestamp(),
        participants: meetings[meetingId].participants.map(p => ({
          userId: p.userId,
          name: p.name,
          email: p.email,
          joinedAt: p.joinedAt
        }))
      }, { merge: true });

      await db.collection('meetingLogs').add({
        meetingId: meetingId,
        userId: socket.userId,
        email: socket.userEmail,
        action: 'joined',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });

      socket.to(meetingId).emit('user-joined', participant);

      const existingParticipants = meetings[meetingId].participants.filter(
        p => p.id !== socket.id
      );
      socket.emit('existing-participants', existingParticipants);

      console.log(`${userName} (${socket.userEmail}) joined meeting ${meetingId}`);
    } catch (error) {
      console.error('Error joining meeting:', error);
      socket.emit('auth-error', 'Failed to join meeting');
    }
  });

  // Handle chat messages
  socket.on('send-message', async ({ roomId, userId, userName, message, timestamp }) => {
    try {
      console.log(`💬 Message from ${userName} in room ${roomId}:`, message);

      if (!socket.userId) {
        socket.emit('auth-error', 'Authentication required to send messages');
        return;
      }

      socket.to(roomId).emit('receive-message', {
        userId: userId,
        userName: userName,
        message: message,
        timestamp: timestamp
      });

      console.log(`✅ Message broadcasted to room ${roomId}`);

      db.collection('chatMessages').add({
        roomId: roomId,
        userId: userId,
        userName: userName,
        message: message,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        createdAt: new Date(timestamp)
      }).catch(err => {
        console.log('Note: Could not save message to Firestore:', err.message);
      });

    } catch (error) {
      console.error('Error sending message:', error);
      socket.emit('message-error', 'Failed to send message');
    }
  });

  // WebRTC Signaling
  socket.on('offer', ({ offer, to, from }) => {
    if (!socket.userId) {
      socket.emit('auth-error', 'Authentication required');
      return;
    }
    io.to(to).emit('offer', { offer, from });
  });

  socket.on('answer', ({ answer, to, from }) => {
    if (!socket.userId) {
      socket.emit('auth-error', 'Authentication required');
      return;
    }
    io.to(to).emit('answer', { answer, from });
  });

  socket.on('ice-candidate', ({ candidate, to, from }) => {
    if (!socket.userId) {
      socket.emit('auth-error', 'Authentication required');
      return;
    }
    io.to(to).emit('ice-candidate', { candidate, from });
  });

  // Leave meeting
  socket.on('leave-meeting', async ({ meetingId }) => {
    try {
      if (meetings[meetingId]) {
        meetings[meetingId].participants = meetings[meetingId].participants.filter(
          p => p.id !== socket.id
        );

        if (meetings[meetingId].participants.length > 0) {
          await db.collection('meetings').doc(meetingId).update({
            participants: meetings[meetingId].participants.map(p => ({
              userId: p.userId,
              name: p.name,
              email: p.email,
              joinedAt: p.joinedAt
            })),
            lastActive: admin.firestore.FieldValue.serverTimestamp()
          });
        } else {
          await db.collection('meetings').doc(meetingId).update({
            endedAt: admin.firestore.FieldValue.serverTimestamp(),
            participants: []
          });
          delete meetings[meetingId];
        }

        await db.collection('meetingLogs').add({
          meetingId: meetingId,
          userId: socket.userId,
          email: socket.userEmail,
          action: 'left',
          timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        socket.to(meetingId).emit('user-left', socket.id);
        socket.leave(meetingId);

        console.log(`${socket.displayName} left meeting ${meetingId}`);
      }
    } catch (error) {
      console.error('Error leaving meeting:', error);
    }
  });

  // Disconnect handler
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id, '-', socket.displayName);

    if (socket.userId && activeSessions[socket.userId]) {
      delete activeSessions[socket.userId];
    }

    Object.keys(meetings).forEach(async (meetingId) => {
      if (meetings[meetingId].participants.some(p => p.id === socket.id)) {
        meetings[meetingId].participants = meetings[meetingId].participants.filter(
          p => p.id !== socket.id
        );

        io.to(meetingId).emit('user-left', socket.id);

        try {
          if (meetings[meetingId].participants.length === 0) {
            await db.collection('meetings').doc(meetingId).update({
              endedAt: admin.firestore.FieldValue.serverTimestamp(),
              participants: []
            });
            delete meetings[meetingId];
          } else {
            await db.collection('meetings').doc(meetingId).update({
              participants: meetings[meetingId].participants.map(p => ({
                userId: p.userId,
                name: p.name,
                email: p.email,
                joinedAt: p.joinedAt
              })),
              lastActive: admin.firestore.FieldValue.serverTimestamp()
            });
          }

          await db.collection('meetingLogs').add({
            meetingId: meetingId,
            userId: socket.userId,
            email: socket.userEmail,
            action: 'disconnected',
            timestamp: admin.firestore.FieldValue.serverTimestamp()
          });
        } catch (error) {
          console.error('Error updating meeting on disconnect:', error);
        }
      }
    });
  });
});

// REST API Endpoints

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    activeMeetings: Object.keys(meetings).length,
    activeSessions: Object.keys(activeSessions).length,
    timestamp: new Date()
  });
});

// AI Chat endpoint with GROQ
app.post('/api/ai-chat', verifyAuthMiddleware, async (req, res) => {
  try {
    const { query, meetingId } = req.body;
    const userId = req.userId;

    if (!query || !query.trim()) {
      return res.status(400).json({ error: 'Query is required' });
    }

    // Rate limiting per user
    const now = Date.now();
    const lastRequest = aiRateLimits.get(userId) || 0;
    const timeSinceLastRequest = now - lastRequest;

    if (timeSinceLastRequest < AI_RATE_LIMIT) {
      const waitTime = Math.ceil((AI_RATE_LIMIT - timeSinceLastRequest) / 1000);
      return res.status(429).json({ 
        error: 'Rate limit exceeded',
        message: `Please wait ${waitTime} seconds before trying again.`,
        waitTime: waitTime
      });
    }

    aiRateLimits.set(userId, now);

    console.log(`🤖 AI API request from user ${userId}:`, query.substring(0, 50) + '...');

    const GROQ_API_KEY = process.env.GROQ_API_KEY;
    
    if (!GROQ_API_KEY) {
      console.error('❌ GROQ_API_KEY not configured');
      return res.status(500).json({ 
        error: 'AI service not configured',
        message: 'Please contact the administrator to enable AI features.'
      });
    }

    const response = await axios({
      url: 'https://api.groq.com/openai/v1/chat/completions',
      method: 'post',
      headers: {
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      data: {
        model: 'llama-3.1-8b-instant', // Fast and free model
        messages: [
          {
            role: 'user',
            content: query
          }
        ],
        temperature: 0.7,
        max_tokens: 800
      },
      timeout: 30000
    });

    console.log('✅ AI API response received');

    const botResponse = response.data?.choices?.[0]?.message?.content || 
      "I apologize, but I couldn't generate a response. Please try again.";

    // Save AI interaction to Firestore
    if (meetingId) {
      db.collection('aiInteractions').add({
        meetingId: meetingId,
        userId: userId,
        query: query,
        response: botResponse,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      }).catch(err => console.log('Note: Could not save AI interaction:', err.message));
    }

    res.json({
      success: true,
      response: botResponse
    });

  } catch (error) {
    console.error('❌ AI API error:', error.response?.data || error.message);

    let statusCode = 500;
    let errorMessage = 'An error occurred while processing your request.';

    if (error.response?.status === 429) {
      statusCode = 429;
      errorMessage = 'API rate limit reached. Please try again in a minute.';
    } else if (error.response?.status === 400) {
      statusCode = 400;
      errorMessage = 'Invalid request. Please try rephrasing your question.';
    } else if (error.code === 'ECONNABORTED') {
      statusCode = 408;
      errorMessage = 'Request timeout. Please try again.';
    } else if (error.response?.data?.error?.message) {
      errorMessage = error.response.data.error.message;
    }

    res.status(statusCode).json({ 
      error: 'AI request failed',
      message: errorMessage,
      details: error.response?.data?.error || error.message
    });
  }
});

// Get chat history
app.get('/chat/:meetingId', async (req, res) => {
  try {
    const { meetingId } = req.params;
    
    const messagesSnapshot = await db.collection('chatMessages')
      .where('roomId', '==', meetingId)
      .limit(100)
      .get();

    const messages = [];
    messagesSnapshot.forEach(doc => {
      const data = doc.data();
      messages.push({ 
        id: doc.id, 
        ...data,
        timestamp: data.timestamp?.toDate ? data.timestamp.toDate().toISOString() : data.createdAt
      });
    });

    messages.sort((a, b) => new Date(a.timestamp || a.createdAt) - new Date(b.timestamp || b.createdAt));

    console.log(`📚 Retrieved ${messages.length} messages for meeting ${meetingId}`);
    res.json({ messages });
  } catch (error) {
    console.error('Error fetching chat history:', error);
    res.json({ messages: [] });
  }
});

// Get meeting info
app.get('/meeting/:meetingId', verifyAuthMiddleware, async (req, res) => {
  try {
    const { meetingId } = req.params;

    const meetingDoc = await db.collection('meetings').doc(meetingId).get();

    if (!meetingDoc.exists) {
      return res.status(404).json({ error: 'Meeting not found' });
    }

    res.json({ meetingId, ...meetingDoc.data() });
  } catch (error) {
    console.error('Error fetching meeting:', error);
    res.status(500).json({ error: 'Failed to fetch meeting info' });
  }
});

// Get user's meeting history
app.get('/user/meetings', verifyAuthMiddleware, async (req, res) => {
  try {
    const logsSnapshot = await db.collection('meetingLogs')
      .where('userId', '==', req.userId)
      .limit(50)
      .get();

    const meetings = [];
    logsSnapshot.forEach(doc => {
      meetings.push({ id: doc.id, ...doc.data() });
    });

    meetings.sort((a, b) => {
      const aTime = a.timestamp?.toDate ? a.timestamp.toDate() : new Date(0);
      const bTime = b.timestamp?.toDate ? b.timestamp.toDate() : new Date(0);
      return bTime - aTime;
    });

    res.json({ meetings });
  } catch (error) {
    console.error('Error fetching user meetings:', error);
    res.status(500).json({ error: 'Failed to fetch meeting history' });
  }
});

// Cleanup old meetings periodically
setInterval(async () => {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const oldMeetingsSnapshot = await db.collection('meetings')
      .where('lastActive', '<', oneHourAgo)
      .get();

    const batch = db.batch();
    oldMeetingsSnapshot.forEach(doc => {
      batch.update(doc.ref, {
        endedAt: admin.firestore.FieldValue.serverTimestamp(),
        participants: []
      });
    });

    await batch.commit();
    console.log(`🧹 Cleaned up ${oldMeetingsSnapshot.size} old meetings`);
  } catch (error) {
    console.error('Error cleaning up meetings:', error);
  }
}, 60 * 60 * 1000);

// Cleanup rate limit map periodically
setInterval(() => {
  const now = Date.now();
  for (const [userId, timestamp] of aiRateLimits.entries()) {
    if (now - timestamp > AI_RATE_LIMIT * 2) {
      aiRateLimits.delete(userId);
    }
  }
}, 60 * 1000);

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔐 Authentication enabled`);
  console.log(`🤖 AI endpoint enabled with Groq`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});