const cipher = require("./security/cipher")
const cors = require("cors")
const bodyParser = require("body-parser")
const sql = require("mysql2")
const dbConf = require("./db/dbconfig.json")
var pool = sql.createPool(dbConf);

/*Environment variables for secrets*/
require("dotenv").config()

/*Express backend manager*/
const express = require("express")

/*Path for resources, node implementation*/
const path = require("path")

const app = express()
const port = process.env.PORT || 3000
const favicon = require("serve-favicon")
const { connect } = require("http2")

//Favicon serving with serve-favicon module.
app.use(favicon(path.join(__dirname,"resources","favicon.ico")))
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('pages'));

//Main functions start here
app.get("/",(request,response) =>{
    response.sendFile(path.join(__dirname + "/pages/index.html"));
})

app.get("/getuser", (request,response)=>{
    const mail = request.query.email;
    const password = request.query.password;
    let psw = cipher.encryptPBKDF2(password);
    pool.query('SELECT * FROM UTENTEAUSL WHERE Email = ? AND Password = ?',[mail, psw],(err,rows,fields)=>{
        response.json(rows[0]);
    })
})

//End of main functions
app.listen(port,()=>{
    console.log("Backend in ascolto sulla porta: " + port)
})

//evita che node si chiuda su un errore
process.on('uncaughtException', function (err) {
    console.log('Caught exception: ', err);
});