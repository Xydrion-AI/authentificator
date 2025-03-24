const passport = require("passport");
const bcryptjs = require("bcryptjs");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const jwt = require("jsonwebtoken");
const JWT_KEY = "cequejeveux";
const JWT_RESET_KEY = "cequejeveuxici";

const User = require('../models/User');
const { info } = require("console");

function isValidPassword(password) {
    const regex = /^(?=.*[\W_]).{8,}$/; // Au moins 8 caractères et un caractère spécial
};

exports.registerHandle = (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Merci de compléter tous les champs' });
    }

    if (password != password2) {
        errors.push({ msg: 'Les mots de passe de correspondent pas' });
    }

    if (!isValidPassword(password)) {
        errors.push({ msg: 'Le mot de passe doit contenir 8 caractères minimum et au moins un caractère spécial' })
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        User.findOne({ email: email }).then(user => { // Recherche d'une donnée spécifique avec findOne
            if (user) {
                errors.push({ msg: 'Cette adresse est déjà associée à un compte' })
                res.render('register', {
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else {
                const oauth2Client = new OAuth2(//OAuth2 prend 3 paramètres obligatoires
                    "CLIENT_ID", // Données API de google fournit par google via la console
                    "CLIENT_SECRET",
                    "REDIRECT_URI"
                );
                oauth2Client.setCredentials({
                    refresh_token: "xxxxx",
                });

                const accessToken = oauth2Client.getAccessToken();

                //pload fonction json web token qui permet de prendre des infos à transférer via l'URL
                const token = jwt.sign({ name, email, password }, JWT_KEY, { expiresIn: '30m' }); //jwt = création token en json
                const CLIENT_URI = 'http://' + req.headers.host;

                const output = `
                    <h2>Cliquer sur le lien suivant pour activer votre compte</h2>
                    <p>${CLIENT_URI}/auth/activate/${token}</p>
                    <p><b>NOTE: </b>le lien expire dans 30 minutes</p>
                `;

                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        type: "OAuth2",
                        user: "xxx@gmail.com",
                        clientId: "xxx",
                        clientSecret: "xxx",
                        refreshToken: "xxx",
                        accessToken: accessToken
                    },
                });

                const mailOptions = {
                    from: '"Roberto" <xxx@gmail.com>',
                    to: email,
                    subject: "Vérification nodeJS authentification",
                    generateTextFromHTML: true,
                    HTML: output
                };

                transporter.sendMail(mailOptions, (errors, info) => {
                    if (errors) {
                        req.flash('error_msg', 'Un problème est survenu pendant l\'envoi de votre mail, veuillez réessayer plus tard');
                        res.redirect('/auth/login');
                    } else {
                        req.flash('success_msg', 'Un lien d\'activation vous a été envoyé par mail');
                        res.redirect('/auth/login');
                    }
                });
            }
        }); //.then = promesse de succès
    }
};