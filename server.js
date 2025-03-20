const express = require("express");
const expressLayouts = require("express-ejs-layouts");
const mongoose = require("mongoose");
const passport = require("passport");
const session = require("express-session");


const app = express();

const db = require('./config/key').mongoURI;

mongoose.connect(db, {useNewUrlParser: true, useUnifiedTopology: true})
    .then(() => console.log("La connexion à MongoDB est établie"))
    .catch(err => console.log(err));

app.use(expressLayouts);
app.use("/assets", express.static('./assets'));
app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));
app.use(
    session({
        secret: 'secret',
        resave: true,
        saveUnitialized: true
    })
);

app.use(passport.initialize());
app.use(passport.session());

app.use('/', require('./routes/index'));
app.use('/auth', require('./routes/auth'));

const PORT = 4001;

app.listen(PORT, console.log(`Serveur http://localhost:${PORT}`));