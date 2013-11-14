/*
* User APIs
* */

var config = require('../config.js'),
    crypto = require('crypto'),
    hat = require('hat'),
    User = require('../models/user.js'),
//  Admin = require('../models/admin.js'),
    check = require('validator').check,
    sanitize = require('validator').sanitize,
    nodemailer = require("nodemailer");

var smtpTransport = nodemailer.createTransport("SMTP", {
    service: config.serviceMailSMTP,
    // host: "smtp.moedns.com", // hostname
    //secureConnection: true, // use SSL
    // port: 465, // port for secure SMTP
    auth: {
        user: config.serviceMailUser,
        pass: config.serviceMailPass
    }
});

// Routes methods

module.exports = function(app) {

    app.get('/', function(req, res) {
        res.end('This is DuoHuo User system.');
    });


}

// Extra functions
function checkIP(ip, callback) {
    if (!config.ipwhitelist) {
        callback(true);
    } else if (config.trustedIPs.indexOf(ip) != -1) {
        callback(true);
    } else {
        callback(false);
    }
}