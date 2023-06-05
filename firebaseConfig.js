const { initializeApp } = require("firebase/app");
const { getFirestore, addDoc, collection, deleteDoc, doc, getDocs, setDoc, getDoc, updateDoc, arrayUnion, arrayRemove } = require("firebase/firestore");
const { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword } = require("firebase/auth");

const firebaseConfig = {
    apiKey: "AIzaSyA0iDJ93wY-_H2tTpSCYvCoire72MTDZ5g",
    authDomain: "slackclone-aab9c.firebaseapp.com",
    projectId: "slackclone-aab9c",
    storageBucket: "slackclone-aab9c.appspot.com",
    messagingSenderId: "921968400137",
    appId: "1:921968400137:web:ef37ac2371f42acb5265d8"
};
const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);
const auth = getAuth()

async function getAllUsers() {
    console.log("getAllUsers")
    const users = [];
    const usersCollection = collection(db, "users");
    const querySnapshot = await getDocs(usersCollection);
    querySnapshot.forEach((doc) => {
        const user = doc.data();
        users.push(user);
    });
    return users;
}

async function getUserByUsername(username) {
    console.log("getUserByUsername")
    const docRef = doc(db, `users/${username}`);
    const user = (await getDoc(docRef)).data();
    return user;
}

async function getAllUsersByUsernames(usernames) {
    const users = [];
    await Promise.all(usernames.map(async (username) => {
      const docRef = doc(db, `users/${username}`);
      const userSnapshot = await getDoc(docRef);
      const user = userSnapshot.data();
      users.push(user);
    }));
  
    return users;
  }

async function addUser(username, public_key, private_key, iv, salt) {
    console.log("addUser")
    const publicChannels = await getAllForcedChannels();
    const publicChannelIds = publicChannels.map(c => c.id)
    const userCollection = collection(db, "users");
    const docRef = doc(userCollection, username);
    await setDoc(docRef, {
        username: username,
        active: false,
        subscriptions: publicChannelIds,
        public_key: public_key,
        private_key_encrypted: private_key,
        iv: iv,
        salt: salt
    });
}

async function addRoom(roomName, options) {
    console.log("addRoom")
    const roomCollection = collection(db, "rooms")
    const doc = await addDoc(roomCollection, {
        name: roomName,
        options: options,
        history: [],
        members: [],
    })
    const room = await getRoomById(doc.id)
    return room
}

async function getAllRooms() {
    console.log("getAllRooms")
    const rooms = [];
    const roomCollection = collection(db, "rooms");
    const querySnapshot = await getDocs(roomCollection);
    querySnapshot.forEach((doc) => {
        const room = doc.data();
        const roomWithId = { id: doc.id, ...room }
        rooms.push(roomWithId);
    });
    return rooms;
}

async function getRoomById(roomID) {
    console.log("getRoomById")
    const docRef = doc(db, `rooms/${roomID}`);
    const room = (await getDoc(docRef)).data();
    room.id = roomID
    return room;
}

async function setActiveState(username, b) {
    console.log("setActiveState")
    const userCollection = collection(db, "users");
    const docRef = doc(userCollection, username);
    await updateDoc(docRef, {
        active: b,
    });
}

async function getAllForcedChannels() {
    console.log("getAllForcedChannels")
    const rooms = await getAllRooms()
    const forcedChannels = rooms.filter(r => r.options.forceMembership);
    return forcedChannels;
}

async function getAllPublicChannels() {
    console.log("getAllPublicChannels")
    const rooms = await getAllRooms()
    const publicChannels = rooms.filter(r => !r.options.direct && !r.options.private);
    return publicChannels;
}

async function addSubscription(user, roomID) {
    const userDoc = doc(db, `users/${user.username}`)
    await updateDoc(userDoc, {
        subscriptions: arrayUnion(roomID)
    })
}

async function removeSubscription(user, roomID) {
    const userDoc = doc(db, `users/${user.username}`)
    await updateDoc(userDoc, {
        subscriptions: arrayRemove(roomID)
    })
}

async function addMember(user, roomID) {
    const roomDoc = doc(db, `rooms/${roomID}`)
    await updateDoc(roomDoc, {
        members: arrayUnion(user.username)
    })
}

async function removeMember(user, roomID) {
    const roomDoc = doc(db, `rooms/${roomID}`)
    await updateDoc(roomDoc, {
        members: arrayRemove(user.username)
    })
}

async function addMessage(msg, roomID) {
    const {username, encrypted_message_hex, encrypted_symmetric_key_hex, room, time} = msg
    const history = room.history
    const toPush = {
        time: time,
        username: username,
        message: encrypted_message_hex,
        roomID: room.id
    }
    history.push(toPush)
    const roomDoc = doc(db, `rooms/${roomID}`)
    await updateDoc(roomDoc, {
        history: history,
        symmetric_key_encrypted: encrypted_symmetric_key_hex
    })
}

async function getMembers(roomID){
    const room = await getRoomById(roomID)
    return room.members
}

async function directRoomExists(user_a, user_b) {
    console.log("directRoomExists")
    const room = await getAllRooms()
    const exists = room.find(r => r.options.direct
        && (
            (r.members[0] == user_a.username && r.members[1] == user_b.username) ||
            (r.members[1] == user_a.username && r.members[0] == user_b.username)
        ))
    return exists
}

async function updateSymmetricKeyFromRoom(roomID, newSymmetricKey){
    const roomDoc = doc(db, `rooms/${roomID}`)
    await updateDoc(roomDoc, {
        symmetric_key_encrypted: newSymmetricKey
    })
}

module.exports = {  
    firebaseApp,
    db,
    auth,
    signInWithEmailAndPassword,
    createUserWithEmailAndPassword,
    collection,
    doc,
    setDoc,
    getDoc,
    addDoc,
    deleteDoc,
    getDocs,
    getUserByUsername,
    getAllUsers,
    addUser,
    getAllRooms,
    getRoomById,
    addRoom,
    setActiveState,
    getAllForcedChannels,
    addSubscription,
    getAllPublicChannels,
    addMember,
    addMessage,
    removeMember,
    removeSubscription,
    directRoomExists,
    getAllUsersByUsernames,
    getMembers,
    updateSymmetricKeyFromRoom
}