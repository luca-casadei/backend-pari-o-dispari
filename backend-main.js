const cipher = require("./security/cipher");
const sql = require("mysql");
const dbConf = require("./db/dbconfig");
const mainConfig = require("./config/generalConfig");
const bodyParser = require("body-parser");
const cors = require("cors");

//Decommentare solo se necessaria una richiesta senza encoding (es. da Native)
const jsonParser = bodyParser.json();

//DB manager
var pool = sql.createPool(dbConf.parameters);

/*Environment variables for secrets*/
require("dotenv").config();

/*Express backend manager*/
const express = require("express");

/*Path for resources, node implementation*/
const path = require("path");

const app = express();
const favicon = require("serve-favicon");

//HTTPS loading
const reader = require("fs");
const https = require("https");
const privateKey = reader.readFileSync("./certificates/casadeiddnsnet.key");
const certificate = reader.readFileSync("./certificates/casadei_ddns_net.pem");
const httpsListener = https.createServer(
  { key: privateKey, cert: certificate },
  app
);

//Favicon serving with serve-favicon module.
app.use(favicon(path.join(__dirname, "resources", "favicon.ico")));
app.use(express.static("pages"));
app.use(cors());

//Main functions start here
app.get("/", (request, response) => {
  response.sendFile(path.join(__dirname + "/pages/index.html"));
});

//FUNZIONI AUSL
app.post("/auslogin", jsonParser, (request, response) => {
  const parsedUser = {
    email: request.body.email,
    password: request.body.password,
  };
  pool.query(
    "SELECT Email,Password FROM UTENTEAUSL WHERE Email = ?",
    [parsedUser.email],
    (err, rows) => {
      if (err) throw err;
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else if (rows[0] == undefined) {
        response.status(404).send("Utente non trovato");
      } else {
        let encPass = cipher.encryptPBKDF2(parsedUser.password);
        if (encPass === rows[0].Password) {
          const token = cipher.getToken(parsedUser);
          response.status(200).send({
            email: parsedUser.email,
            token: token,
          });
        } else {
          response.status(400).send("Credenziali invalide");
        }
      }
    }
  );
});

//FUNZIONI BAMBINO
app.post("/kidlogin", jsonParser, (request, response) => {
  const kidUser = {
    codiceFiscale: request.body.codiceFiscale,
    password: request.body.password,
  };
  pool.query(
    "SELECT Email,Password FROM BAMBINO WHERE CodiceFiscale = ?",
    [kidUser.codiceFiscale],
    (err, rows) => {
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else if (rows[0] == undefined) {
        response.status(404).send("Utente non trovato");
      } else {
        let encPass = cipher.encryptPBKDF2(kidUser.password);
        if (encPass === rows[0].Password) {
          const token = cipher.getToken(kidUser);
          response.status(200).send({
            token: token,
          });
        } else {
          response.status(400).send({ token: undefined });
        }
      }
    }
  );
});

app.post("/getkid", jsonParser, (request, response) => {
  const kidUser = {
    codiceFiscale: request.body.codiceFiscale,
  };
  pool.query(
    "SELECT * FROM BAMBINO WHERE CodiceFiscale = ?",
    [kidUser.codiceFiscale],
    (err, rows) => {
      if (rows[0] != undefined) {
        response.status(200).send(rows[0]);
      } else {
        response.status(404).send("Utente non trovato");
      }
    }
  );
});

app.post("/getkidmenuinfo", jsonParser, (request, response) => {
  const kidParams = {
    codiceFiscale: request.body.codiceFiscale,
  };
  pool.query(
    "SELECT MENU.Id as IdMenu, MENU.EmailCreatore AS EmailCreatoreMenu, MENU.Nome AS NomeMenu, MENUBAMBINO.Stagione AS StagioneMenu " +
    "FROM MENU INNER JOIN MENUBAMBINO ON MENU.Id=MENUBAMBINO.IdMenu WHERE MENUBAMBINO.CodiceFiscaleBambino = ?",
    [kidParams.codiceFiscale],
    (err, rows) => {
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else if (rows[0] == undefined) {
        response.status(404).send("Utente non trovato");
      } else {
        response.status(200).send(rows[0]);
      }
    }
  );
});

app.post("/getkidmenudishes", jsonParser, (request, response) => {
  const kidParams = {
    codiceFiscale: request.body.codiceFiscale,
    idMenu: request.body.idMenu,
  };
  pool.query(
    "SELECT PIATTO.Id,PIATTO.Nome AS NomePiatto,PIATTO.Descrizione FROM MENUBAMBINO " +
    "INNER JOIN MENU ON MENUBAMBINO.IdMenu=MENU.Id INNER JOIN COMPOSIZIONEMENU ON MENU.Id = COMPOSIZIONEMENU.IdMenu " +
    "INNER JOIN PIATTO ON COMPOSIZIONEMENU.IdPiatto = PIATTO.Id WHERE MENUBAMBINO.CodiceFiscaleBambino=? AND MENUBAMBINO.IdMenu=?",
    [kidParams.codiceFiscale, kidParams.idMenu],
    (err, rows) => {
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else if (rows[0] == undefined) {
        response.status(404).send("Utente non trovato");
      } else {
        response.status(200).send(rows);
      }
    }
  );
});

//API per modificare unicamente la password di un bambino
app.post("/setkidpassword", jsonParser, (request, response) => {
  const kidUser = {
    codiceFiscale: request.body.codiceFiscale,
    password: cipher.encryptPBKDF2(request.body.password),
  };
  pool.query(
    "UPDATE BAMBINO SET BAMBINO.Password = ? WHERE CodiceFiscale = ?",
    [kidUser.password, kidUser.codiceFiscale],
    (err, rows) => {
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else {
        response.status(200).send("Password modificata");
      }
    }
  );
});

//API per modificare tutti i campi tolta la password del bambino
app.post("/setkid", jsonParser, (request, response) => {
  const kidUser = {
    codiceFiscale: request.body.codiceFiscale,
    nome: request.body.nome,
    cognome: request.body.cognome,
    dataNascita: request.body.dataNascita,
    email: request.body.email,
  };
  pool.query(
    "UPDATE BAMBINO SET BAMBINO.Nome = ?,BAMBINO.Cognome = ?,BAMBINO.DataNascita = ?, BAMBINO.Email = ?  WHERE CodiceFiscale = ?",
    [
      kidUser.nome,
      kidUser.cognome,
      kidUser.dataNascita,
      kidUser.email,
      kidUser.codiceFiscale,
    ],
    (err, rows) => {
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else {
        response.status(200).send("Password modificata");
      }
    }
  );
});

app.post("/getidmenukid", jsonParser, (request, response) => {
  pool.query(
    "SELECT IdMenu,Stagione FROM MENUBAMBINO WHERE CodiceFiscaleBambino=?",
    request.body.codiceFiscale,
    (err, rows) => {
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else if (rows[0] == undefined) {
        response.status(404).send("Utente non trovato");
      } else {
        response.status(200).send(rows[0]);
      }
    }
  );
});

//FUNZIONI CUCINA
app.post("/cheflogin", jsonParser, (request, response) => {
  const chefUser = {
    username: request.body.username,
    password: request.body.password,
  };
  pool.query(
    "SELECT Username,Password FROM UTENTECUCINA WHERE Username = ?",
    [chefUser.username],
    (err, rows) => {
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else if (rows[0] == undefined) {
        response.status(404).send("Utente non trovato");
      } else {
        let encPass = cipher.encryptPBKDF2(chefUser.password);
        if (encPass === rows[0].Password) {
          const token = cipher.getToken(chefUser);
          response.status(200).send({
            token: token,
          });
        } else {
          response.status(400).send({ token: undefined });
        }
      }
    }
  );
});

app.post("/getchef", jsonParser, (request, response) => {
  const chefUser = {
    username: request.body.username,
    password: request.body.password,
  };
  pool.query(
    "SELECT * FROM UTENTECUCINA WHERE Username = ?",
    [chefUser.username],
    (err, rows) => {
      if (rows[0] != undefined) {
        response.status(200).send(rows[0]);
      } else {
        response.status(404).send("Utente non trovato");
      }
    }
  );
});
app.post("/setchefpassword", jsonParser, (request, response) => {
  const chefUser = {
    username: request.body.username,
    password: cipher.encryptPBKDF2(request.body.password),
  };
  pool.query(
    "UPDATE UTENTECUCINA SET UTENTECUCINA.Password = ? WHERE Username = ?",
    [chefUser.password, chefUser.username],
    (err, rows) => {
      if (rows == undefined) {
        response.status(502).send("Database non raggiungibile");
      } else {
        response.status(200).send("Password modificata");
      }
    }
  );
});

app.post("/getassociazionecucine", jsonParser, (request, response) => {
  const chefUser = {
    username: request.body.username,
  };
  pool.query(
    "SELECT UsernameCucina,CodiceFiscaleBambino,Cognome AS CognomeBambino,Nome AS NomeBambino,DataNascita AS DataNascitaBambino,Email AS EmailBambino FROM ASSOCIAZIONECUCINE JOIN BAMBINO ON ASSOCIAZIONECUCINE.CodiceFiscaleBambino = BAMBINO.CodiceFiscale WHERE UsernameCucina = ?",
    [chefUser.username],
    (err, rows) => {
      if (rows[0] != undefined) {
        response.status(200).send(rows);
      } else {
        response.status(404).send("Utente non trovato");
      }
    }
  );
});

//FUNZIONI DI AUTENTICAZIONE
app.post("/auth", jsonParser, (request, response) => {
  const requestedUser = {
    token: request.body.token,
  };
  let mail = cipher.isTokenValid(requestedUser.token).email;
  if (mail) {
    response.status(200).send({
      valid: true,
      username: mail,
    });
  } else {
    response.status(401).send({
      valid: false,
      username: "",
    });
  }
});

//End of main functions
httpsListener.listen(mainConfig.parameters.listenPort, () => {
  console.log("Backend in ascolto sulla porta: " + mainConfig.parameters.listenPort);
});

//Se capita un errore non fa esplodere node
process.on("uncaughtException", function (err) {
  console.log("Caught exception: ", err);
});
