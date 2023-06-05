class AuthResponse{
    constructor(kind, idToken, email, refreshToken, expiresIn, localId){
        this.kind = kind;
        this.idToken = idToken;
        this.email = email;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.localId = localId
    }
}