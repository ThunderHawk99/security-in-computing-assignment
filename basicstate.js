const { getAllUsers, getAllRooms, getAllPublicChannels } = require("./firebaseConfig");

module.exports = {
    setup: async (Users, Rooms) => {
        Users = await getAllUsers()
        Rooms = await getAllRooms()
    }
}