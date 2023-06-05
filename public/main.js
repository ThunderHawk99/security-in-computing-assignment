$(function () {
  // Initialize variables
  const $window = $(window);
  const $messages = $('.messages'); // Messages area
  const $inputMessage = $('#input-message'); // Input message input box
  const $usernameLabel = $('#user-name');
  const $roomList = $('#room-list');
  const $userList = $('#user-list');
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()

  function saveUserInStorage(username, private_key, iv, salt) {
    const user = {
      username: username,
      private_key: private_key,
      iv: iv,
      salt: salt
    }
    sessionStorage.setItem('user', JSON.stringify(user));
  }

  function getUserFromStorage() {
    const user = JSON.parse(sessionStorage.getItem('user'));
    return user;
  }

  function getUsernameFromStorage() {
    const user = getUserFromStorage()
    if (user) {
      return user.username;
    } else {
      return null;
    }
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

  function setUsername(name, private_key, iv, salt) {
    saveUserInStorage(name, private_key, iv, salt)
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
    const { public_key, encrypted_private_key, iv, salt } = await generateKeyPairs(tpassword)
    socket.emit('register', {
      email: temail,
      username: tusername,
      password: tpassword,
      public_key: arrayBufferToHex(public_key),
      private_key: arrayBufferToHex(encrypted_private_key),
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
    const tprivate = $('#inp-private').is(':checked');
    const iv = crypto.getRandomValues(new Uint8Array(16))
    const salt = crypto.getRandomValues(new Uint8Array(16))
    socket.emit('add_channel', { name: name, description: description, private: tprivate, iv: arrayBufferToHex(iv), salt: arrayBufferToHex(salt) });
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
    $usernameLabel.text("error");
  })

  // Whenever the server emits -login-, log the login message
  socket.on('login', async (data) => {
    const { username, users, rooms, publicChannels, private_key, iv, salt } = data
    setUsername(username, private_key, iv, salt)
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
  socket.on('new message', async (msg) => {
    let { private_key, iv, salt } = getUserFromStorage()
    let { encrypted_message_hex, encrypted_symmetric_key_hex } = msg.data
    //Transform data in correct formats
    iv = hexToArrayBuffer(iv);
    salt = hexToArrayBuffer(salt)
    const encrypted_private_key = hexToArrayBuffer(private_key)
    const encrypted_symmetric_key = hexToArrayBuffer(encrypted_symmetric_key_hex)
    const encrypted_message = hexToArrayBuffer(encrypted_message_hex)
    const room_iv = hexToArrayBuffer(msg.data.room.options.iv)
    const salt_iv = hexToArrayBuffer(msg.data.room.options.iv)
    const decrypted_symmetric_key = await decryptSymmetricKey(encrypted_private_key, encrypted_symmetric_key, iv, salt)
    // Assuming you have exported the symmetric key as `exportedSymmetricKey`
    const imported_decrypted_symmetric_key = await window.crypto.subtle.importKey(
      'raw',
      decrypted_symmetric_key,
      AES_ALGORITHM,
      false,
      ['decrypt']
    );
    // Decrypt the encrypted message using the imported symmetric key
    const decrypted_message = await decryptMessage(encrypted_message, imported_decrypted_symmetric_key, room_iv)
    const roomId = msg.room;
    const room = rooms[roomId];
    if (room) {
      room.history.push(msg);
    }
    if (roomId == currentRoom.id){
      msg.message = decrypted_message
      addChatMessage(msg);
    }
    else
      messageNotify(msg);
  });

  socket.on('new message encrypt', async (data) => {
    const { public_keys, room, message } = data;
    // Step 1: Generate a random symmetric key
    let symmetric_key = await generateSymmetricKey2()
    // Step 2: Encrypt the message content using the symmetric key
    const encoded_message = encoder.encode(message);
    const iv_buffer = hexToArrayBuffer(room.options.iv)
    const encrypted_message_buffer = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: iv_buffer },
      symmetric_key,
      encoded_message
    );
    const encrypted_message_hex = arrayBufferToHex(encrypted_message_buffer);

    symmetric_key = await window.crypto.subtle.exportKey('raw', symmetric_key);
    // Step 3: Encrypt the same used symmetric key with the public keys of the recipients
    const encrypted_symmetric_key_hex = await encryptSymmetricKey(public_keys, symmetric_key);
    socket.emit('new message', {
      username: getUsernameFromStorage(),
      encrypted_message_hex: encrypted_message_hex,
      encrypted_symmetric_key_hex: arrayBufferToHex(encrypted_symmetric_key_hex),
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
    const new_symmetric_key = await generateEncryptedSymmetricKeyFromPublicKeys(data.public_keys)
    socket.emit('update_new_symmetric_key', {
      roomID: data.roomID,
      symmetric_key: arrayBufferToHex(new_symmetric_key)
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
    if (getUserFromStorage() != undefined) {
      socket.emit('join', getUsernameFromStorage())
    }
  });

  socket.on('disconnect', () => {
  });

  socket.on('reconnect', () => {
    // join
    if (getUserFromStorage() != undefined) {
      socket.emit('join', getUsernameFromStorage());
    }
  });

  socket.on('reconnect_error', () => {
  });

});
