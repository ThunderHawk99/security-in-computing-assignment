const { getRoomById, getAllRooms, addRoom } = require("./firebaseConfig");

const rooms = [];
class Room {
    constructor(id, name, options) {
        this.id   =  id;
        this.name =  name;

        this.description = options.description || "";
      
        this.forceMembership = !!options.forceMembership;
        this.private         = !!options.private;
        this.direct          = !!options.direct;
  
        this.members = [];
        this.history = [];
    }
}