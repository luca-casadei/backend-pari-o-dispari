const cipher = require("./security/cipher")
const sql = require("mysql2")
const dbConf = require("./db/dbconfig.json")
const bodyParser = require("body-parser")

//Decommentare solo se necessaria una richiesta senza encoding (es. da Native)
//const jsonParser = bodyParser.json()

const urlEncodedParser = bodyParser.urlencoded({extended:false});
var pool = sql.createPool(dbConf);

/*Environment variables for secrets*/
require("dotenv").config()

/*Express backend manager*/
const express = require("express")

/*Path for resources, node implementation*/
const path = require("path")

const app = express()
const port = process.env.PORT || 3000
const favicon = require("serve-favicon");

//Favicon serving with serve-favicon module.
app.use(favicon(path.join(__dirname,"resources","favicon.ico")))
app.use(express.static('pages'));

//Main functions start here
app.get("/",(request,response) =>{
    response.sendFile(path.join(__dirname + "/pages/index.html"));
})

app.post("/auslogin",urlEncodedParser,(request,response)=>{
    const parsedUser ={
        email: request.body.email,
        password: request.body.password
    }
    pool.query("SELECT Email,Password FROM UTENTEAUSL WHERE Email = ?",[parsedUser.email],(err,rows)=>{
        if(rows[0] != undefined){
            let encPass = cipher.encryptPBKDF2(parsedUser.password);
            if(encPass === rows[0].Password){
                const token = cipher.getToken(parsedUser);
                response.status(200).send({
                    email: parsedUser.email,
                    token: token
                });
            }
            else{
                response.status(400).send("Credenziali invalide");
            }
        }
        else{
            response.status(404).send("Utente non trovato");
        }
    })
})

app.post("/auth",urlEncodedParser, (request,response) =>{
    const requestedUser = {
        email: request.body.email,
        token: request.body.token
    }
    if(cipher.isTokenValid(requestedUser.token)){
        response.status(200).send({
            valid:true
        });
    }
    else{
        response.status(401).send({
            valid:false
        });
    }
})

//End of main functions
app.listen(port,()=>{
    console.log("Backend in ascolto sulla porta: " + port)
})

//evita che node si chiuda su un errore
process.on('uncaughtException', function (err) {
    console.log('Caught exception: ', err);
});