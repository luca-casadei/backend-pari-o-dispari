const crypto = require("crypto");

//Ritorna una stringa esadecimale con il testo cifrato a chiave simmetrica.
function encryptPBKDF2(plainText){
    if (plainText != undefined){
        let salt = process.env.SALT;
        return crypto.pbkdf2Sync(plainText,salt,1000,64,'sha512').toString('hex');
    }
    else{
        return "";
    }
}

module.exports = {encryptPBKDF2};