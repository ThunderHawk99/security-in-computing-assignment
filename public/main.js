$(function () {
  // Initialize variables
  const $window = $(window);
  const $messages = $('.messages'); // Messages area
  const $inputMessage = $('#input-message'); // Input message input box
  const $usernameLabel = $('#user-name');
  const $roomList = $('#room-list');
  const $userList = $('#user-list');
  const encoder = new TextEncoder()

  function generateSessionKey() {
    // Create an array to store the random bytes
    const keyBytes = new Uint8Array(32); // 32 bytes = 256 bits
    // Generate random values and fill the array with them
    crypto.getRandomValues(keyBytes);
    // Convert the byte array to a string representation
    const sessionKey = Array.from(keyBytes)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');

    return sessionKey;
  }

  ////////////////
  // Encryption //
  ////////////////
  const RSA_ALGORITHM = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537 - commonly used and recommended value for the public exponent
    hash: { name: 'SHA-256' },
  };
  const AES_ALGORITHM = {
    name: 'AES-CBC',
    length: 256
  }
  const EXTRACTABLE = true;
  const USAGES = ['encrypt', 'decrypt'];

  async function deriveEncryptionKeyFromPassword(password, salt) {
    const PASSWORD_DERIVATION_ALGORITHM = {
      name: 'PBKDF2',
      salt: salt, // Generate a random salt value
      iterations: 100000,
      hash: 'SHA-256'
    }
    // Convert the password to an encryption key using a key derivation function
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      PASSWORD_DERIVATION_ALGORITHM,
      false,
      ['deriveKey']
    );
    // Derive an AES symmetric key from the password key
    const aesDerivedKey = await crypto.subtle.deriveKey(
      PASSWORD_DERIVATION_ALGORITHM,
      passwordKey,
      AES_ALGORITHM,
      EXTRACTABLE,
      USAGES
    );
    return aesDerivedKey;
  }



  async function encryptPrivateKey(password, private_key) {
    // Generate a random salt
    const salt = crypto.getRandomValues(new Uint8Array(16))
    // Get our symmetric key from our password to encrypt the private_key with it
    const aesDerivedKey = await deriveEncryptionKeyFromPassword(password, salt)
    // Generate a random Initialization Vector (IV)
    const iv = crypto.getRandomValues(new Uint8Array(16));
    // Encrypt the private key with the derived AES key
    const encryptedPrivateKeyBuffer = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      // So we encrypt the private_key with the aes symmetric key
      aesDerivedKey,
      private_key
    );
    // Convert the encrypted private key to hex format
    const encryptedPrivateKeyHex = arrayBufferToHex(encryptedPrivateKeyBuffer);
    // Return the encrypted private key in hex format
    return { encryptedPrivateKeyHex, iv, salt };
  }

  async function decryptPrivateKey(password, encryptedPrivateKeyHex, iv, salt) {
    // Convert the password to an encryption key using a key derivation function and then derive an AES key from the password key
    const aesDerivedKey = await deriveEncryptionKeyFromPassword(password, salt)
    // Convert the encrypted private key from hex to ArrayBuffer
    const encryptedPrivateKeyBuffer = hexToArrayBuffer(encryptedPrivateKeyHex);
    // Decrypt the private key with the derived AES key
    const decryptedPrivateKeyBuffer = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      aesDerivedKey,
      encryptedPrivateKeyBuffer
    );
    // Return the decrypted private key as an ArrayBuffer
    return decryptedPrivateKeyBuffer;
  }

  async function generateKeyPairs(password) {
    console.log("GENERATE")
    let { publicKey, privateKey } = await crypto.subtle.generateKey(
      RSA_ALGORITHM,
      EXTRACTABLE,
      USAGES
    );
    // Export public key in SPKI format and convert to hex string
    const exportedPublicKey = await crypto.subtle.exportKey('spki', publicKey);
    const publicKeyHex = arrayBufferToHex(exportedPublicKey);
    // Convert public key to hex string
    // Export and encrypt private key with the password
    const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', privateKey);
    const { encryptedPrivateKeyHex, iv, salt } = await encryptPrivateKey(password, exportedPrivateKey);
    return { publicKeyHex, encryptedPrivateKeyHex, iv, salt }
  }

  function arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .reduce((hexString, byte) => hexString + byte.toString(16).padStart(2, '0'), '');
  }

  function hexToArrayBuffer(hexString) {
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
      const byte = parseInt(hexString.substr(i, 2), 16);
      bytes[i / 2] = byte;
    }
    return bytes.buffer;
  }

  // Generate a random symmetric key
  async function generateSymmetricKey() {
    const key = await window.crypto.subtle.generateKey(
      AES_ALGORITHM,
      EXTRACTABLE,
      USAGES
    );
    return key;
  }

  // Encrypt the symmetric key with a user's public key
  async function encryptSymmetricKey(symmetric_key, public_key) {
    const importedPublicKey = await window.crypto.subtle.importKey(
      'spki',
      hexToArrayBuffer(public_key),
      {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-256' },
      },
      false,
      ['encrypt']
    );
    const encryptedKey = await window.crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP',
      },
      importedPublicKey,
      hexToArrayBuffer(symmetric_key)
    );
    return encryptedKey;
  }

  async function generateEncryptedSymmetricKey(public_keys) {
    try {
      let symmetric_key = await generateSymmetricKey();
      for (const pk of public_keys) {
        symmetric_key = await encryptSymmetricKey(symmetric_key, pk);
      }
      return arrayBufferToHex(symmetric_key);
    } catch (ex) {
      console.error('Error generating encrypted symmetric key:', ex);
    }
  }

  async function generateNewEncryptSymmetricKey(public_keys, symmetric_key) {
    try {
      for (const pk of public_keys) {
        symmetric_key = await encryptSymmetricKey(symmetric_key, pk);
      }
      return arrayBufferToHex(symmetric_key);
    } catch (ex) {
      console.error('Error generating encrypted symmetric key:', ex);
    }
  }


  // Usage
  const sessionKey = generateSessionKey();
  // console.log(sessionKey);

  function saveUsernameInStorage(username) {
    sessionStorage.setItem('username', username);
  }

  function getUsernameFromStorage() {
    const username = sessionStorage.getItem('username');
    return username;
  }

  let connected = false;
  let socket = io();

  let modalShowing = false;
  let loginModalShowing = false
  let registerModalShowing = false

  $('#addChannelModal').on('hidden.bs.modal', () => modalShowing = false)
    .on('show.bs.modal', () => modalShowing = true);

  $('#loginModal').on('hidden.bs.modal', () => loginModalShowing = false)
    .on('show.bs.modal', () =>
      loginModalShowing = true
    );
  $('#registerModal').on('hidden.bs.modal', () => registerModalShowing = false)
    .on('show.bs.modal', () =>
      registerModalShowing = true
    );
  $("#loginModal").modal('show');

  function setUsername(name) {
    saveUsernameInStorage(name)
    $usernameLabel.text(name);
  }
  window.setUsername = setUsername;

  function login() {
    const temail = $("#inp-email").val();
    const tusername = $("#inp-username").val();
    const tpassword = $("#inp-password").val();
    socket.emit('login', { email: temail, username: tusername, password: tpassword });
  }
  window.login = login;

  async function register() {
    const temail = $("#inp-email-reg").val();
    const tusername = $("#inp-username-reg").val();
    const tpassword = $("#inp-password-reg").val();
    const { publicKeyHex, encryptedPrivateKeyHex, iv, salt } = await generateKeyPairs(tpassword)
    socket.emit('register', {
      email: temail,
      username: tusername,
      password: tpassword,
      public_key: publicKeyHex,
      private_key: encryptedPrivateKeyHex,
      iv: arrayBufferToHex(iv),
      salt: arrayBufferToHex(salt)
    });
  }
  window.register = register

  ///////////////
  // User List //
  ///////////////
  let users = {};

  function updateUsers(p_users) {
    p_users.forEach(u => users[u.username] = u);
    updateUserList();
  }

  function updateUser(username, active) {
    if (!users[username])
      users[username] = { username: username };

    users[username].active = active;

    updateUserList();
  }

  function updateUserList() {
    const $uta = $("#usersToAdd");
    $uta.empty();

    $userList.empty();
    for (let [un, user] of Object.entries(users)) {
      if (getUsernameFromStorage() !== user.username)
        $userList.append(`
          <li onclick="setDirectRoom(this)" data-direct="${user.username}" class="${user.active ? "online" : "offline"}">${user.username}</li>
        `);
      // append it also to the add user list
      $uta.append(`
          <button type="button" class="list-group-item list-group-item-action" data-dismiss="modal" onclick="addToChannel('${user.username}')">${user.username}</button>
        `);
    };
  }

  ///////////////
  // Room List //
  ///////////////

  let rooms = [];

  function updateRooms(p_rooms) {
    rooms = p_rooms;
    updateRoomList();
  }

  function updateRoom(room) {
    let index = rooms.findIndex(r => r.id === room.id);
    index === -1 ? rooms.push(room) : rooms[index] = room;
    updateRoomList();
  }

  function removeRoom(id) {
    delete rooms[id];
    updateRoomList();
  }

  function updateRoomList() {
    $roomList.empty();
    rooms.forEach(r => {
      if (!r.options.direct)
        $roomList.append(`
          <li onclick="setRoom('${r.id}')"  data-room="${r.id}" class="${r.private ? "private" : "public"}">${r.name}</li>
        `);
    });
  }


  function updateChannels(channels) {
    const c = $("#channelJoins");

    c.empty();
    channels.forEach(r => {
      if (!rooms[r.id])
        c.append(`
          <button type="button" class="list-group-item list-group-item-action" data-dismiss="modal" onclick="joinChannel(${r.id})">${r.name}</button>
        `);
    });
  }


  //////////////
  // Chatting //
  //////////////

  let currentRoom = false;

  function setRoom(id) {
    let oldRoom = currentRoom;
    const room = rooms.find(r => r.id === id);
    currentRoom = room;
    $messages.empty();
    if (room.history) {
      room.history.forEach(m => addChatMessage(m));
    }
    $userList.find('li').removeClass("active");
    $roomList.find('li').removeClass("active");
    if (room.options.direct) {
      const idx = room.members.indexOf(getUsernameFromStorage()) == 0 ? 1 : 0;
      const user = room.members[idx];
      setDirectRoomHeader(user);

      $userList.find(`li[data-direct="${user}"]`)
        .addClass("active")
        .removeClass("unread")
        .attr('data-room', room.id);

    } else {
      $('#channel-name').text("#" + room.name);
      $('#channel-description').text(`👤 ${room.members.length} | ${room.options.description}`);
      $roomList.find(`li[data-room=${room.id}]`).addClass("active").removeClass("unread");
    }

    $('.roomAction').css('visibility', (room.options.direct || room.options.forceMembership) ? "hidden" : "visible");
  }
  window.setRoom = setRoom;

  function setDirectRoomHeader(user) {
    $('#channel-name').text(user);
    $('#channel-description').text(`Direct message with ${user}`);
  }

  function setToDirectRoom(username) {
    setDirectRoomHeader(username);
    $messages.empty()
    socket.emit('request_direct_room', { to: username });
  }

  window.setDirectRoom = (el) => {
    const user = el.getAttribute("data-direct");
    const room = el.getAttribute("data-room");

    if (room) {
      setRoom(room);
    } else {
      setToDirectRoom(user);
    }
  }

  function sendMessage() {
    let message = $inputMessage.val();

    if (message && connected && currentRoom !== false && getUsernameFromStorage()) {
      $inputMessage.val('');
      const msg = { username: getUsernameFromStorage(), message: message, room: currentRoom };

      // addChatMessage(msg);
      socket.emit('new message unencrypted', msg);
    }
  }


  function addChatMessage(msg) {
    let time = new Date(msg.time).toLocaleTimeString('en-US', {
      hour12: false,
      hour: "numeric",
      minute: "numeric"
    });

    $messages.append(`
      <div class="message">
        <div class="message-avatar"></div>
        <div class="message-textual">
          <span class="message-user">${msg.username}</span>
          <span class="message-time">${time}</span>
          <span class="message-content">${msg.message}</span>
        </div>
      </div>
    `);

    $messages[0].scrollTop = $messages[0].scrollHeight;
  }

  function messageNotify(msg) {
    if (msg.direct)
      $userList.find(`li[data-direct="${msg.username}"]`).addClass('unread');
    else
      $roomList.find(`li[data-room=${msg.room}]`).addClass("unread");
  }


  function addChannel() {
    const name = $("#inp-channel-name").val();
    const description = $("#inp-channel-description").val();
    const private = $('#inp-private').is(':checked');
    const iv = crypto.getRandomValues(new Uint8Array(16))
    const salt = crypto.getRandomValues(new Uint8Array(16))
    socket.emit('add_channel', { name: name, description: description, private: private, iv: arrayBufferToHex(iv), salt: arrayBufferToHex(salt) });
  }
  window.addChannel = addChannel;


  function joinChannel(id) {
    socket.emit('join_channel', { id: id });
  }
  window.joinChannel = joinChannel;

  function addToChannel(user) {
    socket.emit('add_user_to_channel', { channel: currentRoom.id, user: user });
  }
  window.addToChannel = addToChannel;

  function leaveChannel() {
    socket.emit('leave_channel', { id: currentRoom.id });
  }
  window.leaveChannel = leaveChannel;

  /////////////////////
  // Keyboard events //
  /////////////////////

  $window.keydown(event => {
    if (modalShowing || loginModalShowing || registerModalShowing)
      return;

    // Autofocus the current input when a key is typed
    if (!(event.ctrlKey || event.metaKey || event.altKey)) {
      $inputMessage.focus();
    }

    // When the client hits ENTER on their keyboard
    if (event.which === 13) {
      sendMessage();
    }

    // don't add newlines
    if (event.which === 13 || event.which === 10) {
      event.preventDefault();
    }
  });

  ///////////////////
  // server events //
  ///////////////////

  socket.on('login_error', req => {
    console.log("sqsdfqsdf")
    setUsername("error")
  })

  // Whenever the server emits -login-, log the login message
  socket.on('login', async (data) => {
    const {username, users, rooms, publicChannels} = data
    setUsername(username)
    connected = true;
    updateUsers(users);
    updateRooms(rooms);
    updateChannels(publicChannels);
    if (rooms.length > 0) {
      const currentRoom = rooms.find(r => r.options.forceMembership)
      setRoom(currentRoom.id);
    }
  });

  socket.on('update_public_channels', (data) => {
    console.log('update_public_channels')
    updateChannels(data.publicChannels);
  });

  // Whenever the server emits 'new message', update the chat body
  socket.on('new message', (msg) => {
    console.log(msg)
    const roomId = msg.room;
    const room = rooms[roomId];
    if (room) {
      room.history.push(msg);
    }
    if (roomId == currentRoom.id)
      addChatMessage(msg);
    else
      messageNotify(msg);
  });

  socket.on('new message encrypt', async (data) => {
    const { public_keys, room, message } = data;
    // Step 1: Generate a random symmetric key
    const symmetric_key = await generateSymmetricKey()

    // Step 2: Encrypt the message content using the symmetric key
    const encoded_message = encoder.encode(message);
    const iv_buffer = hexToArrayBuffer(room.options.iv)
    const encrypted_message_buffer = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: iv_buffer },
      symmetric_key,
      encoded_message
    );
    const encrypted_message_hex = arrayBufferToHex(encrypted_message_buffer);

    // Step 3: Encrypt the symmetric key with the public keys of the recipients
    const encrypted_symmetric_key_hex = await generateNewEncryptSymmetricKey(public_keys, symmetric_key);
    socket.emit('new message', {
      username: getUsernameFromStorage(),
      encrypted_message_hex: encrypted_message_hex,
      encrypted_symmetric_key_hex: encrypted_symmetric_key_hex,
      room: room
    })
  })

  socket.on('update_user', data => {
    console.log('update_user')
    const room = rooms[data.room];
    if (room) {
      room.members = data.members;

      if (room === currentRoom)
        setRoom(data.room);
    }
  });

  socket.on('user_state_change', (data) => {
    console.log('user_state_change')
    updateUser(data.username, data.active);
  });

  socket.on('update_room', data => {
    console.log("UPDATE_ROOM")
    updateRoom(data.room);
    if (data.moveto)
      setRoom(data.room.id);
  });

  socket.on('added_channel', data => {
    console.log("added_channel")
    updateRoom(data.room);
    if (data.moveto)
      setRoom(data.room.id);
    socket.emit('get_public_keys_from_room', data.room.id)
  });

  socket.on('generate_new_symmetric_key', async (data) => {
    const new_symmetric_key = await generateEncryptedSymmetricKey(data.public_keys)
    socket.emit('update_new_symmetric_key', {
      roomID: data.roomID,
      symmetric_key: new_symmetric_key
    })
  })

  socket.on('remove_room', data => {
    removeRoom(data.room);
    if (currentRoom.id == data.room)
      setRoom(0);
  });

  ////////////////
  // Connection //
  ////////////////

  socket.on('connect', () => {
    if (getUsernameFromStorage() != undefined) {
      socket.emit('join', getUsernameFromStorage())
    }
  });

  socket.on('disconnect', () => {
  });

  socket.on('reconnect', () => {
    // join
    if (getUsernameFromStorage() != undefined) {
      socket.emit('join', getUsernameFromStorage());
    }
  });

  socket.on('reconnect_error', () => {
  });

});
