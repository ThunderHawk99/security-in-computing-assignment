////////////////
// Encryption //
////////////////
const encoder = new TextEncoder()
const decoder = new TextDecoder()
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

// Generate a public key, encrypted private key, iv and salt for a new user
async function generateKeyPairs(password) {
    let { publicKey, privateKey } = await crypto.subtle.generateKey(
        RSA_ALGORITHM,
        EXTRACTABLE,
        USAGES
    );
    // Export public key in spki format
    const public_key = await crypto.subtle.exportKey('spki', publicKey);
    // Export private key in pkcs8 format, encrypt it with password
    const private_key = await crypto.subtle.exportKey('pkcs8', privateKey);
    const { encrypted_private_key, iv, salt } = await encryptPrivateKey(password, private_key);
    // Important to return iv and salt that was used during the encryption of the private key
    // There are needed again when decrypting the private key
    return { public_key, encrypted_private_key, iv, salt }
}

// Encrypt the private key with password
async function encryptPrivateKey(password, private_key) {
    // Generate a random salt
    const salt = crypto.getRandomValues(new Uint8Array(16))
    // Get our symmetric key from our password to encrypt the private_key with it
    const aes_derived_key = await deriveEncryptionKeyFromPassword(password, salt)
    // Generate a random Initialization Vector (IV)
    const iv = crypto.getRandomValues(new Uint8Array(16));
    // Encrypt the private key with the derived AES key
    const encrypted_private_key = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv },
        // So we encrypt the private_key with the aes symmetric key
        aes_derived_key,
        private_key
    );
    // Return the encrypted private key in hex format
    return { encrypted_private_key, iv, salt };
}

// Decrypt the private key with password
async function decryptPrivateKey(password, encrypted_private_key, iv, salt) {
    try {
        // Convert the password to an encryption key using a key derivation function and then derive an AES key from the password key
        const aes_derived_key = await deriveEncryptionKeyFromPassword(password, salt)
        // Convert the encrypted private key from hex to ArrayBuffer
        // Decrypt the private key with the derived AES key
        const decrypted_private_key = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv },
            aes_derived_key,
            encrypted_private_key
        );
        return decrypted_private_key;
    } catch (ex) {
        console.log(ex)
    }
}

// Derive an encryption key from password
async function deriveEncryptionKeyFromPassword(password, salt) {
    const PASSWORD_DERIVATION_ALGORITHM = {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
    }
    // Convert the password to an encryption key using a key derivation function
    const password_key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        PASSWORD_DERIVATION_ALGORITHM,
        false,
        ['deriveKey']
    );
    // Derive an AES symmetric key from the password key
    const aes_derived_key = await crypto.subtle.deriveKey(
        PASSWORD_DERIVATION_ALGORITHM,
        password_key,
        AES_ALGORITHM,
        EXTRACTABLE,
        USAGES
    );
    return aes_derived_key;
}

// Generate a random symmetric key
async function generateSymmetricKey() {
    const key = await window.crypto.subtle.generateKey(
        AES_ALGORITHM,
        EXTRACTABLE,
        USAGES
    );

    // Export the key value as an ArrayBuffer
    const symmetric_key = await window.crypto.subtle.exportKey('raw', key);
    return symmetric_key;
}

async function generateSymmetricKey2() {
    const key = await window.crypto.subtle.generateKey(
        AES_ALGORITHM,
        EXTRACTABLE,
        USAGES
    );

    return key;
}

// Encrypt the symmetric key with a user's public key
async function encryptSymmetricKeyWithPublicKey(symmetric_key, public_key) {
    const importedPublicKey = await window.crypto.subtle.importKey(
        'spki',
        public_key,
        RSA_ALGORITHM,
        false,
        ['encrypt']
    );
    const encryptedKey = await window.crypto.subtle.encrypt(
        RSA_ALGORITHM,
        importedPublicKey,
        symmetric_key
    );
    return encryptedKey;
}

async function generateEncryptedSymmetricKeyFromPublicKeys(public_keys) {
    try {
        let symmetric_key = await generateSymmetricKey();
        for (const pk of public_keys) {
            const public_key = hexToArrayBuffer(pk)
            symmetric_key = await encryptSymmetricKeyWithPublicKey(symmetric_key, public_key);
        }
        return symmetric_key;
    } catch (ex) {
        console.error('Error generating encrypted symmetric key:', ex);
    }
}

async function encryptSymmetricKey(public_keys, symmetric_key) {
    try {
        for (const pk of public_keys) {
            const public_key = hexToArrayBuffer(pk)
            symmetric_key = await encryptSymmetricKeyWithPublicKey(symmetric_key, public_key);
        }
        return symmetric_key;
    } catch (ex) {
        console.error('Error generating encrypted symmetric key:', ex);
    }
}

async function decryptSymmetricKey(encrypted_private_key, encrypted_symmetric_key, iv, salt) {
    // Decrypt private key
    const decrypted_private_key = await decryptPrivateKey("satasa123", encrypted_private_key, iv, salt)
    const imported_decrypted_private_key = await crypto.subtle.importKey(
        'pkcs8',
        decrypted_private_key,
        RSA_ALGORITHM,
        false,
        ['decrypt']
    );
    // Decrypt the encrypted symmetric key using your private key
    const decrypted_symmetric_key = await crypto.subtle.decrypt(
        RSA_ALGORITHM,
        imported_decrypted_private_key,
        encrypted_symmetric_key
    );
    return decrypted_symmetric_key
}

async function decryptMessage(encrypted_message, imported_decrypted_symmetric_key, room_iv) {
    const decrypted_message = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: room_iv },
        imported_decrypted_symmetric_key,
        encrypted_message
    );
    return decoder.decode(decrypted_message)
}

async function decryptMessages(private_key, iv, salt, msg){
    let { encrypted_message_hex, encrypted_symmetric_key_hex } = msg.data
    //Transform data in correct formats
    iv = hexToArrayBuffer(iv);
    salt = hexToArrayBuffer(salt)
    const encrypted_private_key = hexToArrayBuffer(private_key)
    const encrypted_symmetric_key = hexToArrayBuffer(encrypted_symmetric_key_hex)
    const encrypted_message = hexToArrayBuffer(encrypted_message_hex)
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