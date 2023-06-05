// Setup basic express server
const express = require('express');
const app = express();
const path = require('path');
const server = require('http').createServer(app);
const io = require('socket.io')(server);
const port = process.env.PORT || 3000;
const Rooms = require('./rooms.js');
const Users = require('./users.js');
const { auth, signInWithEmailAndPassword, createUserWithEmailAndPassword, addUser, getAllUsers, getUserByUsername, setActiveState, getAllRooms, getRoomById, addRoom, addSubscription, getAllPublicChannels, addMember, addMessage, removeMember, removeSubscription, directRoomExists, getAllForcedChannels, getAllUsersByUsernames, getMembers, updateSymmetricKeyFromRoom } = require("./firebaseConfig");

// Load application config/state
require('./basicstate.js').setup(Users, Rooms);

// Start server
server.listen(port, () => {
  console.log('Server listening on port %d', port);
});

// Routing for client-side files
app.use(express.static(path.join(__dirname, 'public')));

///////////////////////////////
// Chatroom helper functions //
///////////////////////////////

function sendToRoom(room, event, data) {
  io.to('room' + room.id).emit(event, data);
}

async function newRoom(name, user, options) {
  const room = await addRoom(name, options);
  await addUserToRoom(user, room);
  return room;
}

async function newChannel(name, description, private, user, iv, salt) {
  return await newRoom(name, user, {
    description: description,
    private: private,
    iv: iv,
    salt: salt
  });
}

async function newDirectRoom(user_a, user_b) {
  const room = await addRoom(`Direct-${user_a.username}-${user_b.username}`, {
    direct: true,
    private: true,
  });

  await addUserToRoom(user_a, room);
  await addUserToRoom(user_b, room);

  return room;
}

async function getDirectRoom(user_a, user_b) {
  const exists = await directRoomExists(user_a, user_b)
  if (exists) {
    return exists;
  } else {
    return newDirectRoom(user_a, user_b);
  }
}

async function addUserToRoom(user, room) {
  await addSubscription(user, room.id);
  await addMember(user, room.id);
  const members = await getMembers(room.id)
  sendToRoom(room, 'update_user', {
    room: room,
    username: user,
    action: 'added',
    members: members
  });
}

async function removeUserFromRoom(user, room) {
  removeSubscription(user, room.id);
  removeMember(user, room.id);
  const members = await getMembers(room.id)

  sendToRoom(room, 'update_user', {
    room: room.id,
    username: user,
    action: 'removed',
    members: members
  });
}

async function addMessageToRoom(roomId, username, msg) {
  const {room, encrypted_message_hex} = msg
  msg.time = new Date().getTime();

  if (room) {
    sendToRoom(room, 'new message', {
      username: username,
      message:  encrypted_message_hex,
      room: room.id,
      time: msg.time,
      direct: room.direct,
      data: msg
    });
    await addMessage(msg, room.id)
  }
}

async function setUserActiveState(socket, username, state) {
  const user = await getUserByUsername(username);

  if (user)
    await setActiveState(username, state);

  socket.broadcast.emit('user_state_change', {
    username: username,
    active: state
  });
}

///////////////////////////
// IO connection handler //
///////////////////////////

const socketmap = {};

io.on('connection', (socket) => {
  let userLoggedIn = false;
  let username = false;

  socket.on('login', async (req) => {
    signInWithEmailAndPassword(auth, req.email, req.password)
      .then(async (data) => {
        username = req.username
        userLoggedIn = true;
        const rooms = await getAllRooms()
        const publicChannels = rooms.filter(r => !r.options.direct && !r.options.private);
        rooms.forEach(r => socket.join('room' + r.id))
        socket.emit('login', {
          users: await getAllUsers(),
          rooms: rooms,
          publicChannels: publicChannels,
          username: username
        });
      })
      .catch((error) => {
        const errorMessage = error.message;
        console.log(errorMessage)
        socket.emit('login_error', {
          error: errorMessage
        })
      });
  });

  socket.on('register', async (req) => {
    createUserWithEmailAndPassword(auth, req.email, req.password)
      .then(async (data) => {
        username = req.username
        userLoggedIn = true;
        const rooms = await getAllRooms()
        const publicChannels = rooms.filter(r => !r.options.direct && !r.options.private);
        await addUser(username, req.public_key, req.private_key, req.iv, req.salt)
        socket.emit('login', {
          users: await getAllUsers(),
          rooms: await getAllRooms(),
          publicChannels: publicChannels,
          username: username
        });
      })
      .catch((error) => {
        const errorMessage = error.message;
        console.log(errorMessage)
        socket.emit('register_error', {
          error: errorMessage
        })
      });
  });


  ///////////////////////
  // incomming message //
  ///////////////////////

  socket.on('new message', async (msg) => {
    const {username, room} = msg
    if (userLoggedIn) {
      await addMessageToRoom(room.id, username, msg);
    }
  });

  socket.on('new message unencrypted', async (msg) => {
    // const room = await getRoomById(msg.room.id)
    const room = msg.room
    const usernames = await getAllUsersByUsernames(room.members)
    const public_keys = usernames.map(u => u.public_key)
    socket.emit('new message encrypt', {
      public_keys: public_keys,
      room: room,
      message: msg.message
    })
  });

  /////////////////////////////
  // request for direct room //
  /////////////////////////////


  socket.on('request_direct_room', async (req) => {
    if (userLoggedIn) {
      const user_a = await getUserByUsername(req.to);
      const user_b = await getUserByUsername(username);

      if (user_a && user_b) {
        const room = await getDirectRoom(user_a, user_b);
        const roomCID = 'room' + room.id;
        socket.join(roomCID);
        if (socketmap[user_a.username])
          socketmap[user_a.username].join(roomCID);

        socket.emit('update_room', {
          room: room,
          moveto: true
        });
      }
    }
  });

  socket.on('add_channel', async (req) => {
    if (userLoggedIn) {
      const user = await getUserByUsername(username);
      const room = await newChannel(req.name, req.description, req.private, user, req.iv, req.salt);
      const roomCID = 'room' + room.id;
      socket.join(roomCID);

      socket.emit('added_channel', {
        room: room,
        moveto: true
      });

      if (!room.private) {
        const publicChannels = await getAllPublicChannels()
        socket.broadcast.emit('update_public_channels', {
          publicChannels: publicChannels
        });
      }
    }
  });

  socket.on('get_public_keys_from_room', async(roomID) => {
    const room = await getRoomById(roomID)
    const public_keys = await (await getAllUsersByUsernames(room.members)).map(u => u.public_key)
    socket.emit('generate_new_symmetric_key', {
      public_keys:public_keys,
      roomID: room.id
    })
  })

  socket.on('update_new_symmetric_key', async (data) => {
    await updateSymmetricKeyFromRoom(data.roomID, data.symmetric_key)
  })

  socket.on('join_channel', async (req) => {
    if (userLoggedIn) {
      const user = await getUserByUsername(username);
      const room = await getRoomById(req.id);

      if (!room.direct && !room.private) {
        await addUserToRoom(user, room);
        const roomCID = 'room' + room.id;
        socket.join(roomCID);

        socket.emit('update_room', {
          room: room,
          moveto: true
        });
      }
    }
  });


  socket.on('add_user_to_channel', async (req) => {
    if (userLoggedIn) {
      const user = await getUserByUsername(req.user);
      const room = await getRoomById(req.channel)
      if (!room.direct) {
        // Add user to members of the room
        await addUserToRoom(user, room);
        if (socketmap[user.username]) {
          const roomCID = 'room' + room.id;
          socketmap[user.username].join(roomCID);
          socketmap[user.username].emit('update_room', {
            room: room,
            moveto: false
          });
        }
        const public_keys = await (await getAllUsersByUsernames(room.members)).map(u => u.public_key)
        socket.emit('generate_new_symmetric_key', {
          public_keys:public_keys,
          roomID: room.id
        })
      }
    }
  });

  socket.on('leave_channel', async (req) => {
    if (userLoggedIn) {
      const user = await getUserByUsername(username);
      const room = await getRoomById(req.id)

      if (!room.direct && !room.forceMembership) {
        await removeUserFromRoom(user, room);

        const roomCID = 'room' + room.id;
        socket.leave(roomCID);

        socket.emit('remove_room', {
          room: room.id
        });
      }
    }
  });

  ///////////////
  // user join //
  ///////////////

  socket.on('join', async (p_username) => {
    username = p_username;
    if (userLoggedIn)
      return;
    userLoggedIn = true;
    socketmap[username] = socket;
    const user = await getUserByUsername(username)
    if (user) {
      user.subscriptions.map(async (s) => {
        socket.join('room' + s);
        return await getRoomById(s);
      });
      const rooms = await getAllRooms()
      const publicChannels = rooms.filter(r => !r.direct && !r.private);
      socket.emit('login', {
        users: await getAllUsers(),
        rooms: rooms,
        publicChannels: publicChannels
      });

      await setUserActiveState(socket, username, true);
    }
  });


  ////////////////
  // reconnects //
  ////////////////

  socket.on('reconnect', async () => {
    if (userLoggedIn)
      await setUserActiveState(socket, username, true);
  });

  /////////////////
  // disconnects //
  /////////////////

  socket.on('disconnect', async () => {
    if (userLoggedIn)
      await setUserActiveState(socket, username, false);
  });

});
