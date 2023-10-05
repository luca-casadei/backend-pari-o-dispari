require("dotenv").config();

var parameters = {
    "host": "www.pariodispari.com",
    "user": "sagnfmit_apis",
    "password": process.env.DB_PASSWORD,
    "database": "sagnfmit_pariodisparidb",
    "waitForConnections": true,
    "connectionLimit": 10,
    "maxIdle": 10,
    "idleTimeout": 60000,
    "queueLimit": 0,
    "enableKeepAlive": true,
    "keepAliveInitialDelay": 0,
    "port": 3306
}

module.exports = {parameters}