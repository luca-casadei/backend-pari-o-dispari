require("dotenv").config()
const express = require("express")
const path = require("node:path")
const app = express()
const port = process.env.PORT || 3000
const favicon = require("serve-favicon")
app.use(favicon(path.join(__dirname,"resources","favicon.ico")))

app.get("/",(request,response) =>{
    response.send("Ciao mondo!")
})

app.listen(port,()=>{
    console.log("Backend in ascolto...")
})