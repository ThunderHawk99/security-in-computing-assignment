module.exports = {
    setup: (Users, Rooms) => {
        Rooms.addRoom("random" , {forceMembership: true, description: "Random!"});
        Rooms.addRoom("general", {forceMembership: true, description: "interesting things"});
        Rooms.addRoom("private" ,{forceMembership: true, description: "some very private channel", private: true});
    }
}