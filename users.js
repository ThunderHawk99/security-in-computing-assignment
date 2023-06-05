const { addUser, getAllUsers, getUserById, setUserActiveState, getUserByUsername } = require("./firebaseConfig");

const users = {}

class User {
    constructor(name) {
        this.name = name;
        this.active = false;
        this.subscriptions = [];
    }
}