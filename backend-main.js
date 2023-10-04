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
const { verify } = require("crypto");

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

app.post("/kidlogin",urlEncodedParser,(request,response)=>{
    const kidUser ={
        codiceFiscale: request.body.email,
        password: request.body.password
    }
    pool.query("SELECT Email,Password FROM BAMBINO WHERE Email = ?",[kidUser.email],(err,rows)=>{
        if(rows[0] != undefined){
            let encPass = cipher.encryptPBKDF2(kidUser.password);
            if(encPass === rows[0].Password){
                response.status(200).send(rows[0].Email);
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

app.post("/getkid",urlEncodedParser,(request,response)=>{
    const kidUser ={
        codiceFiscale: request.body.email,
        password: request.body.password,
        token:request.body.token
    }
    if(cipher.isTokenValid(token)){
        pool.query("SELECT * FROM BAMBINO WHERE Email = ?",[kidUser.email],(err,rows)=>{
            if(rows[0] != undefined){
                let encPass = cipher.encryptPBKDF2(kidUser.password);
                if(encPass === rows[0].Password){
                    response.status(200).send(rows[0].Email);
                }
                else{
                    response.status(400).send("Credenziali invalide");
                }
            }
            else{
                response.status(404).send("Utente non trovato");
            }
        })
    }
})

app.post("/getkidmenu",urlEncodedParser,(request,response)=>{
    const kidParams = {
        codiceFiscale:request.body.codiceFiscale,
        idMenu:request.body.idMenu,
        token:request.body.token
    }
    if(cipher.isTokenValid(kidParams.token)){
        pool.query("SELECT PIATTO.Id,PIATTO.Nome,PIATTO.Descrizione,MENU.Nome,MENUBAMBINO.Stagione FROM MENUBAMBINO "+
        "INNER JOIN MENU ON MENUBAMBINO.IdMenu=MENU.Id INNER JOIN COMPOSIZIONEMENU ON MENU.Id = COMPOSIZIONEMENU.IdMenu "+ 
        "INNER JOIN PIATTO ON COMPOSIZIONEMENU.IdPiatto = Piatto.Id WHERE MENUBAMBINO.CodiceFiscale=? AND MENUBAMBINO.IdMenu=?",[kidParams.codiceFiscale,kidParams.idMenu],(err,rows)=>{
        if(rows[0] != undefined){
            response.json(rows[0]);
        }
        else{
            response.status(404).send("Menu non trovato");
        }
    })
    }
})

//End of main functions
app.listen(port,()=>{
    console.log("Backend in ascolto sulla porta: " + port)
})

//evita che node si chiuda su un errore
process.on('uncaughtException', function (err) {
    console.log('Caught exception: ', err);
})