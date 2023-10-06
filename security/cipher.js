const crypto = require("crypto");
const jwt = require("jsonwebtoken");

module.exports = {
  //Ritorna una stringa esadecimale con il testo cifrato a chiave simmetrica.
  encryptPBKDF2: (plainText) => {
    if (plainText != undefined) {
      let salt = process.env.SALT;
      return crypto
        .pbkdf2Sync(plainText, salt, 1000, 64, "sha512")
        .toString("hex");
    } else {
      return "";
    }
  },

  getToken: (user) => {
    const token = jwt.sign({ email: user.email }, process.env.TOKEN_KEY, {
      expiresIn: "2h",
    });
    return token;
  },

  isTokenValid: (token) => {
    try {
      return jwt.verify(token, process.env.TOKEN_KEY);
    } catch (error) {
      return false;
    }
  },
};
