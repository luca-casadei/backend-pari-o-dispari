/*Environment variables for secrets*/
require("dotenv").config()
/*Express backend manaer*/
const express = require("express")
/*Path for resources, node implementation*/
const path = require("node:path")

const app = express()
const port = process.env.PORT || 3000
const favicon = require("serve-favicon")

//Favicon serving with serve-favicon module.
app.use(favicon(path.join(__dirname,"resources","favicon.ico")))

//Main functions start here
app.get("/",(request,response) =>{
    response.send("Ciao mondo!")
})


//End of main functions
app.listen(port,()=>{
    console.log("Backend in ascolto sulla porta: " + port)
})