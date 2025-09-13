const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: './config/.env' });

const app = express();
const server = http.createServer(app);

// Production-ready origin list
const allowedOrigins = [
  "http://localhost:5173", 
  "http://localhost:3000", 
  "http://127.0.0.1:5173", 
  "http://localhost:8080", 
  "http://127.0.0.1:8080",
  "https://nightstay.vercel.app",
  "https://teenpatti-server.onrender.com"
];

// Add any additional origins from environment variable
if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

// Socket.IO setup with CORS
const io = socketIo(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS middleware
app.use(cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true
}));

// JWT Helper Functions
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user._id, 
      name: user.name,
      balance: user.balance 
    },
    process.env.JWT_KEY,
    { expiresIn: process.env.JWT_EXPIRY || '7d' }
  );
};

const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_KEY);
};

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ MongoDB connected successfully');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    process.exit(1);
  }
};

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  pin: {
    type: String,
    required: true,
    length: 4,
    match: /^\d{4}$/
  },
  balance: {
    type: Number,
    default: 20000
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// Game Room Schema
const gameRoomSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  players: [{
    username: String,
    balance: Number,
    isActive: { type: Boolean, default: true },
    hasPacked: { type: Boolean, default: false },
    socketId: String
  }],
  entryFee: {
    type: Number,
    default: 500
  },
  pot: {
    type: Number,
    default: 0
  },
  currentPlayerIndex: {
    type: Number,
    default: 0
  },
  gameStarted: {
    type: Boolean,
    default: false
  },
  roundActive: {
    type: Boolean,
    default: false
  },
  status: {
    type: String,
    enum: ['waiting', 'playing', 'finished'],
    default: 'waiting'
  },
  winner: {
    username: String,
    amount: Number
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastActivity: {
    type: Date,
    default: Date.now
  }
});

const GameRoom = mongoose.model('GameRoom', gameRoomSchema);

// Routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Teen Patti Server is running!',
    status: 'active',
    timestamp: new Date().toISOString()
  });
});

// Get all users
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, '-__v');
    res.json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching users',
      error: error.message
    });
  }
});

// Get user by name
app.get('/api/users/:name', async (req, res) => {
  try {
    const user = await User.findOne({ name: req.params.name }, '-__v');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching user',
      error: error.message
    });
  }
});

// Create new user
app.post('/api/users', async (req, res) => {
  try {
    const { name, pin, balance } = req.body;
    
    // Validation
    if (!name || !pin) {
      return res.status(400).json({
        success: false,
        message: 'Name and PIN are required'
      });
    }
    
    if (!/^\d{4}$/.test(pin)) {
      return res.status(400).json({
        success: false,
        message: 'PIN must be exactly 4 digits'
      });
    }

    const user = new User({
      name: name.toLowerCase(),
      pin,
      balance: balance || 20000
    });

    await user.save();
    
    // Generate JWT token for new user
    const token = generateToken(user);
    
    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        name: user.name,
        balance: user.balance,
        token: token
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({
        success: false,
        message: 'User with this name already exists'
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Error creating user',
        error: error.message
      });
    }
  }
});

// Update user balance
app.put('/api/users/:name/balance', async (req, res) => {
  try {
    const { balance } = req.body;
    
    if (typeof balance !== 'number' || balance < 0) {
      return res.status(400).json({
        success: false,
        message: 'Balance must be a non-negative number'
      });
    }

    const user = await User.findOneAndUpdate(
      { name: req.params.name },
      { balance },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Balance updated successfully',
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating balance',
      error: error.message
    });
  }
});

// Authenticate user
app.post('/api/auth', async (req, res) => {
  try {
    const { name, pin } = req.body;
    
    if (!name || !pin) {
      return res.status(400).json({
        success: false,
        message: 'Name and PIN are required'
      });
    }

    const user = await User.findOne({ name: name.toLowerCase() });
    
    if (!user || user.pin !== pin) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate JWT token
    const token = generateToken(user);

    res.json({
      success: true,
      message: 'Authentication successful',
      data: {
        name: user.name,
        balance: user.balance,
        token: token
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Authentication error',
      error: error.message
    });
  }
});

// Verify JWT token and get current user
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    // Get updated user data from database
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Token is valid',
      data: {
        name: user.name,
        balance: user.balance
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Token verification error',
      error: error.message
    });
  }
});

// Game Room Routes
// Get all active rooms
app.get('/api/rooms', async (req, res) => {
  try {
    const rooms = await GameRoom.find({ 
      status: { $in: ['waiting', 'playing'] },
      lastActivity: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
    }).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      count: rooms.length,
      data: rooms
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching rooms',
      error: error.message
    });
  }
});

// Create new room
app.post('/api/rooms', async (req, res) => {
  try {
    const { name, entryFee = 500, creatorUsername } = req.body;
    
    if (!name || !creatorUsername) {
      return res.status(400).json({
        success: false,
        message: 'Room name and creator username are required'
      });
    }

    // Check if user exists
    const user = await User.findOne({ name: creatorUsername.toLowerCase() });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.balance < entryFee) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance for entry fee'
      });
    }

    const room = new GameRoom({
      name: name.trim(),
      entryFee,
      players: [{
        username: user.name,
        balance: user.balance,
        isActive: true,
        hasPacked: false
      }]
    });

    await room.save();
    
    res.status(201).json({
      success: true,
      message: 'Room created successfully',
      data: room
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error creating room',
      error: error.message
    });
  }
});

// Join room
app.post('/api/rooms/:roomId/join', async (req, res) => {
  try {
    const { roomId } = req.params;
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({
        success: false,
        message: 'Username is required'
      });
    }

    const room = await GameRoom.findById(roomId);
    if (!room) {
      return res.status(404).json({
        success: false,
        message: 'Room not found'
      });
    }

    if (room.status !== 'waiting') {
      return res.status(400).json({
        success: false,
        message: 'Cannot join room - game already started'
      });
    }

    // Check if user already in room
    if (room.players.some(p => p.username === username.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: 'Already in this room'
      });
    }

    // Check if user exists and has enough balance
    const user = await User.findOne({ name: username.toLowerCase() });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.balance < room.entryFee) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance for entry fee'
      });
    }

    // Add player to room
    room.players.push({
      username: user.name,
      balance: user.balance,
      isActive: true,
      hasPacked: false
    });

    room.lastActivity = new Date();
    await room.save();

    // Notify all players in the room
    io.to(roomId).emit('playerJoined', {
      room: room,
      newPlayer: user.name
    });

    res.json({
      success: true,
      message: 'Joined room successfully',
      data: room
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error joining room',
      error: error.message
    });
  }
});

// Get room details
app.get('/api/rooms/:roomId', async (req, res) => {
  try {
    const room = await GameRoom.findById(req.params.roomId);
    if (!room) {
      return res.status(404).json({
        success: false,
        message: 'Room not found'
      });
    }

    res.json({
      success: true,
      data: room
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching room',
      error: error.message
    });
  }
});

// Delete room
app.delete('/api/rooms/:roomId', async (req, res) => {
  try {
    const { roomId } = req.params;
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({
        success: false,
        message: 'Username is required to delete room'
      });
    }

    const room = await GameRoom.findById(roomId);
    if (!room) {
      return res.status(404).json({
        success: false,
        message: 'Room not found'
      });
    }

    // Check if the user is the creator (first player) of the room
    if (room.players.length === 0 || room.players[0].username !== username.toLowerCase()) {
      return res.status(403).json({
        success: false,
        message: 'Only the room creator can delete the room'
      });
    }

    // If game is in progress, don't allow deletion
    if (room.gameStarted || room.status === 'playing') {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete room while game is in progress'
      });
    }

    // Notify all players in the room that it's being deleted
    io.to(roomId).emit('roomDeleted', {
      message: 'Room has been deleted by the creator',
      roomId: roomId
    });

    // Delete the room
    await GameRoom.findByIdAndDelete(roomId);

    res.json({
      success: true,
      message: 'Room deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting room',
      error: error.message
    });
  }
});

// Socket.IO Connection Handling
const connectedUsers = new Map(); // Map socketId to username

io.on('connection', (socket) => {
  console.log(`🔌 User connected: ${socket.id}`);

  // User joins a room
  socket.on('joinRoom', async (data) => {
    try {
      const { roomId, username } = data;
      
      // Store user info
      connectedUsers.set(socket.id, { username, roomId });
      
      // Join socket room
      socket.join(roomId);
      
      // Update player's socket ID in database
      await GameRoom.findByIdAndUpdate(
        roomId,
        { 
          $set: { 
            "players.$[elem].socketId": socket.id,
            lastActivity: new Date()
          }
        },
        { arrayFilters: [{ "elem.username": username }] }
      );

      // Get updated room data
      const room = await GameRoom.findById(roomId);
      
      // Notify all players in room
      io.to(roomId).emit('roomUpdate', room);
      
      console.log(`👤 ${username} joined room ${roomId}`);
    } catch (error) {
      console.error('Error joining room:', error);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });

  // Start game
  socket.on('startGame', async (data) => {
    try {
      const { roomId, username } = data;
      const room = await GameRoom.findById(roomId);
      
      if (!room || room.gameStarted) {
        socket.emit('error', { message: 'Cannot start game' });
        return;
      }

      // Check if user is in room
      const player = room.players.find(p => p.username === username);
      if (!player) {
        socket.emit('error', { message: 'Not authorized to start game' });
        return;
      }

      if (room.players.length < 2) {
        socket.emit('error', { message: 'Need at least 2 players to start' });
        return;
      }

      // Deduct entry fee from all players
      for (let player of room.players) {
        if (player.balance >= room.entryFee) {
          player.balance -= room.entryFee;
          room.pot += room.entryFee;
          
          // Update user balance in database
          await User.findOneAndUpdate(
            { name: player.username },
            { $inc: { balance: -room.entryFee } }
          );
        }
      }

      // Start the game
      room.gameStarted = true;
      room.roundActive = true;
      room.status = 'playing';
      room.currentPlayerIndex = Math.floor(Math.random() * room.players.length);
      room.lastActivity = new Date();
      
      await room.save();

      // Notify all players
      io.to(roomId).emit('gameStarted', room);
      
      console.log(`🎮 Game started in room ${roomId}`);
    } catch (error) {
      console.error('Error starting game:', error);
      socket.emit('error', { message: 'Failed to start game' });
    }
  });

  // Player action (bet, blind, pack)
  socket.on('playerAction', async (data) => {
    try {
      const { roomId, username, action, amount } = data;
      const room = await GameRoom.findById(roomId);
      
      if (!room || !room.roundActive) {
        socket.emit('error', { message: 'Game not active' });
        return;
      }

      const currentPlayer = room.players[room.currentPlayerIndex];
      if (currentPlayer.username !== username) {
        socket.emit('error', { message: 'Not your turn' });
        return;
      }

      let nextPlayerIndex = room.currentPlayerIndex;

      switch (action) {
        case 'bet':
        case 'blind':
          if (amount > currentPlayer.balance) {
            socket.emit('error', { message: 'Insufficient balance' });
            return;
          }
          
          currentPlayer.balance -= amount;
          room.pot += amount;
          
          // Update user balance in database
          await User.findOneAndUpdate(
            { name: username },
            { $inc: { balance: -amount } }
          );
          
          // Move to next player
          nextPlayerIndex = getNextActivePlayer(room, room.currentPlayerIndex);
          break;

        case 'pack':
          currentPlayer.isActive = false;
          currentPlayer.hasPacked = true;
          
          // Check if only one player remaining
          const activePlayers = room.players.filter(p => p.isActive && !p.hasPacked);
          if (activePlayers.length === 1) {
            // Game ends
            const winner = activePlayers[0];
            winner.balance += room.pot;
            
            // Update winner's balance in database
            await User.findOneAndUpdate(
              { name: winner.username },
              { $inc: { balance: room.pot } }
            );
            
            room.winner = {
              username: winner.username,
              amount: room.pot
            };
            room.roundActive = false;
            room.status = 'finished';
            
            io.to(roomId).emit('gameEnded', {
              room: room,
              winner: winner.username,
              amount: room.pot
            });
            
            await room.save();
            return;
          } else {
            nextPlayerIndex = getNextActivePlayer(room, room.currentPlayerIndex);
          }
          break;
      }

      room.currentPlayerIndex = nextPlayerIndex;
      room.lastActivity = new Date();
      await room.save();

      // Notify all players
      io.to(roomId).emit('gameUpdate', {
        room: room,
        action: action,
        player: username,
        amount: amount
      });

    } catch (error) {
      console.error('Error processing player action:', error);
      socket.emit('error', { message: 'Failed to process action' });
    }
  });

  // Handle admin kick player
  socket.on('kickPlayer', async (data) => {
    try {
      const { roomId, targetUsername, adminUsername } = data;
      
      const room = await GameRoom.findById(roomId);
      if (!room) {
        socket.emit('error', { message: 'Room not found' });
        return;
      }

      // Check if admin is the room creator (first player)
      if (room.players.length === 0 || room.players[0].username !== adminUsername.toLowerCase()) {
        socket.emit('error', { message: 'Only room creator can kick players' });
        return;
      }

      // Find and remove the target player
      const playerIndex = room.players.findIndex(p => p.username === targetUsername.toLowerCase());
      if (playerIndex === -1) {
        socket.emit('error', { message: 'Player not found' });
        return;
      }

      if (playerIndex === 0) {
        socket.emit('error', { message: 'Cannot kick the room creator' });
        return;
      }

      // Remove player from room
      const kickedPlayer = room.players[playerIndex];
      room.players.splice(playerIndex, 1);
      
      // Adjust currentPlayerIndex if necessary
      if (room.currentPlayerIndex >= playerIndex) {
        room.currentPlayerIndex = Math.max(0, room.currentPlayerIndex - 1);
      }

      await room.save();

      // Notify all players
      io.to(roomId).emit('playerKicked', {
        kickedPlayer: kickedPlayer.username,
        room: room,
        message: `${kickedPlayer.username} has been kicked from the room`
      });

      console.log(`👢 Player ${kickedPlayer.username} kicked from room ${roomId} by ${adminUsername}`);
    } catch (error) {
      console.error('Error kicking player:', error);
      socket.emit('error', { message: 'Failed to kick player' });
    }
  });

  // Handle credit request
  socket.on('requestCredit', async (data) => {
    try {
      const { roomId, requesterUsername, amount } = data;
      
      const room = await GameRoom.findById(roomId);
      if (!room) {
        socket.emit('error', { message: 'Room not found' });
        return;
      }

      // Check if requester is in the room
      const requester = room.players.find(p => p.username === requesterUsername.toLowerCase());
      if (!requester) {
        socket.emit('error', { message: 'You are not in this room' });
        return;
      }

      // Check if player is bankrupt
      if (requester.balance > 0) {
        socket.emit('error', { message: 'You can only request credit when bankrupt' });
        return;
      }

      // Notify all other players about the credit request
      socket.to(roomId).emit('creditRequest', {
        requester: requesterUsername,
        amount: amount,
        roomId: roomId,
        message: `${requesterUsername} is requesting ₹${amount} credit`
      });

      console.log(`💰 Credit request: ${requesterUsername} requesting ₹${amount} in room ${roomId}`);
    } catch (error) {
      console.error('Error processing credit request:', error);
      socket.emit('error', { message: 'Failed to request credit' });
    }
  });

  // Handle credit response
  socket.on('respondToCredit', async (data) => {
    try {
      const { roomId, donorUsername, requesterUsername, amount, accepted } = data;
      
      if (!accepted) {
        // Credit rejected
        io.to(roomId).emit('creditRejected', {
          requester: requesterUsername,
          donor: donorUsername,
          message: `${donorUsername} rejected ${requesterUsername}'s credit request`
        });
        return;
      }

      const room = await GameRoom.findById(roomId);
      if (!room) {
        socket.emit('error', { message: 'Room not found' });
        return;
      }

      // Find donor and requester
      const donor = room.players.find(p => p.username === donorUsername.toLowerCase());
      const requester = room.players.find(p => p.username === requesterUsername.toLowerCase());

      if (!donor || !requester) {
        socket.emit('error', { message: 'Player not found' });
        return;
      }

      // Check if donor has enough balance
      if (donor.balance < amount) {
        socket.emit('error', { message: 'Insufficient balance to provide credit' });
        return;
      }

      // Transfer money
      donor.balance -= amount;
      requester.balance += amount;

      // Update database
      await User.updateOne({ name: donorUsername.toLowerCase() }, { balance: donor.balance });
      await User.updateOne({ name: requesterUsername.toLowerCase() }, { balance: requester.balance });
      await room.save();

      // Notify all players
      io.to(roomId).emit('creditAccepted', {
        donor: donorUsername,
        requester: requesterUsername,
        amount: amount,
        room: room,
        message: `${donorUsername} provided ₹${amount} credit to ${requesterUsername}`
      });

      console.log(`💸 Credit transfer: ${donorUsername} gave ₹${amount} to ${requesterUsername}`);
    } catch (error) {
      console.error('Error processing credit response:', error);
      socket.emit('error', { message: 'Failed to process credit response' });
    }
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    const userInfo = connectedUsers.get(socket.id);
    if (userInfo) {
      console.log(`🔌 User disconnected: ${userInfo.username} from room ${userInfo.roomId}`);
      
      // You might want to handle player disconnection here
      // For now, we'll just remove from connected users
      connectedUsers.delete(socket.id);
    }
  });
});

// Helper function to get next active player
function getNextActivePlayer(room, currentIndex) {
  const activePlayers = room.players.filter(p => p.isActive && !p.hasPacked);
  if (activePlayers.length <= 1) return currentIndex;

  let nextIndex = (currentIndex + 1) % room.players.length;
  while (room.players[nextIndex].hasPacked || !room.players[nextIndex].isActive) {
    nextIndex = (nextIndex + 1) % room.players.length;
  }
  return nextIndex;
}

// Function to seed dummy users
const seedUsers = async () => {
  try {
    const dummyUsers = [
      { name: 'mark', pin: '1234', balance: 20000 },
      { name: 'shubham', pin: '5678', balance: 20000 },
      { name: 'prerit', pin: '5414', balance: 20000 }
    ];

    for (const userData of dummyUsers) {
      const existingUser = await User.findOne({ name: userData.name });
      if (existingUser) {
        // Update existing user's PIN and balance
        await User.updateOne(
          { name: userData.name },
          { pin: userData.pin, balance: userData.balance }
        );
        console.log(`🔄 Updated user: ${userData.name} (PIN: ${userData.pin})`);
      } else {
        // Create new user
        await User.create(userData);
        console.log(`🌱 Created user: ${userData.name} (PIN: ${userData.pin})`);
      }
    }
    
    console.log('✅ Dummy users setup completed');
  } catch (error) {
    console.error('❌ Error seeding users:', error.message);
  }
};

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  });
});

// Start server
const PORT = process.env.PORT || 3000;

const startServer = async () => {
  await connectDB();
  await seedUsers();
  
  server.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`� Socket.IO enabled for real-time communication`);
    console.log(`�📋 API endpoints:`);
    console.log(`   GET    /api/users       - Get all users`);
    console.log(`   GET    /api/users/:name - Get user by name`);
    console.log(`   POST   /api/users       - Create new user`);
    console.log(`   PUT    /api/users/:name/balance - Update user balance`);
    console.log(`   POST   /api/auth        - Authenticate user`);
    console.log(`   GET    /api/auth/verify - Verify JWT token`);
    console.log(`   GET    /api/rooms       - Get all rooms`);
    console.log(`   POST   /api/rooms       - Create new room`);
    console.log(`   POST   /api/rooms/:id/join - Join room`);
    console.log(`   GET    /api/rooms/:id   - Get room details`);
    console.log(`   DELETE /api/rooms/:id   - Delete room (creator only)`);
  });
};

startServer().catch(console.error);

module.exports = app;
