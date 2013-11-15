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

// Status object
function returnStatus (status, message, user) {
    this.status = status;
    this.message = message;
    this.user = user;
}
// Routes methods

module.exports = function(app) {

    app.get('/', function(req, res) {
        res.end(JSON.stringify(new returnStatus('OK', 'This is DuoHuo User system.', null)));
    });

    app.post('/reg', checkIP, function(req, res) {
        var name = req.body.username,
            mail = req.body.email,
            password = req.body.password,
            siteurl= req.body.siteurl;
        // We dont need to check if password equals to repeat-password
        // repeatPassword = req.body['password-repeat'];

        try {
            check(name, 'USERNAME_EMPTY').notEmpty();
            check(name, 'USERNAME_MUST_ALPHANUMERIC').isAlphanumeric();
            check(password, 'PASSWORD_EMPTY').notEmpty();
            check(mail, 'EMAIL_INVALID').len(4, 64).isEmail();
        } catch (e) {
            return res.end(JSON.stringify(new returnStatus('ERROR', e.message, null)));
        }

        // get password hash
        var hash = crypto.createHash('sha256'),
            password = hash.update(req.body.password).digest('hex');
        var newUser = new User({
            name: name,
            password: password,
            email: mail,
            activekey: hat(),
            role: 'inactive'
        });
        // check if username exists.
        User.check(newUser.name, newUser.email, function(err, user){
            // console.log(user);
            if(user) {
                err.message = 'USER_EXISTS';
            }
            if(err) {
                return res.end(JSON.stringify(new returnStatus('ERROR', err.message, null)));
            }
            newUser.save(function(err){
                if(err){
                    return res.end(JSON.stringify(new returnStatus('ERROR', err.message, null)));
                }
                // Send verification Email.
                var activeLink = 'http://' + config.url + '/activate?activekey=' + newUser.activekey + '&go=' + siteurl;
                if (config.ssl) {
                    activeLink = 'https://' + config.url + '/activate?activekey=' + newUser.activekey + '&go=' + siteurl;
                }
                // console.log(activeLink);
                var mailOptions = {
                    from: config.serviceMailSender, // sender address
                    to: newUser.email, // list of receivers
                    subject: res.__('USER_VERIFICATION_SUBJECT') + ' - ' + config.siteName, // Subject line
                    text: res.__('USER_VERIFICATION_BODY', newUser.name, config.siteName, activeLink)
                }
                // console.log(mailOptions.text);
                // send mail with defined transport object
                smtpTransport.sendMail(mailOptions, function(err, response) {
                    // console.log('executed');
                    if (err) {
                        console.log(err);
                        return res.end(JSON.stringify(new returnStatus('ERROR', err.message, null)));
                    }
                    smtpTransport.close();
                    // req.session.user = newUser; // store user information to session.
                    res.end(JSON.stringify(new returnStatus('OK', 'USER_CREATED', newUser)));
                });

            });
        });
    });

    // TODO render page for user activate.
    app.get('/activate', function(req, res) {
        var activekey = req.query.activekey;
        User.checkActivekey(activekey, function(err, user) {
            if (err) {
                res.write(err.message);
                return res.redirect(req.query.siteurl);
            }

            if (!user) {
                res.write('User activated not exist.');
                return res.redirect(req.query.siteurl);
            }

            User.activate(activekey, function(err) {
                if (err) {
                    res.write(err.message);
                    return res.redirect(req.query.siteurl);
                }
                res.write('User activated.');
                res.redirect(req.query.siteurl);
            });
        });
    });

    app.post('/login', checkIP, function(req, res){
        // Generate password hash
        var hash = crypto.createHash('sha256'),
            password = hash.update(req.body.password).digest('hex'),
            ip = req.body.ipaddress
        // check login details
        try {
            check(req.body.username, 'USERNAME_MUST_ALPHANUMERIC').isAlphanumeric();
        } catch (e) {
            return res.end(JSON.stringify(new returnStatus('ERROR', e.message, null)))
        }
        User.get(req.body.username, function(err, user) {
            if (!user) {
                res.end(JSON.stringify(new returnStatus('ERROR', 'USER_NOT_EXIST', null)));
            } else if (user.password != password) {
                // Send warning message.
                var mailOptions = {
                    from: config.serviceMailSender,
                    to: user.email,
                    subject: res.__('LOGIN_FAIL_WARNING_SUBJECT') + ' - ' + config.siteName,
                    text: res.__('LOGIN_FAIL_WARNING_BODY', ip)
                }
                // send mail with defined transport object
                smtpTransport.sendMail(mailOptions, function(err, response) {
                    // console.log('executed');
                    if (err) {
                        console.log(err);
                    }
                    smtpTransport.close();
                    res.end(JSON.stringify(new returnStatus('ERROR', 'LOGIN_FAILED', null)));
                });
            } else {
                if (user.role == 'inactive') {
                    res.end(JSON.stringify(new returnStatus('ERROR', 'USER_NOT_ACTIVATED', null)));
                } else {
                    res.end(JSON.stringify(new returnStatus('OK', 'LOGIN_SUCCESS', user)));
                }
            }
        });
    });


}

// Extra functions
function checkIP(req, res, next) {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    if (!config.ipwhitelist) {
        next();
    } else if (config.trustedIPs.indexOf(ip) != -1) {
        next();
    } else {
        res.send(403, 'Forbidden.');
    }
}