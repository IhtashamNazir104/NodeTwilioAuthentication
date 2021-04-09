var express = require('express')
var router = express.Router()
var db = require('../database/connection')
var jwt = require('jsonwebtoken')
var bcrypt = require ('bcrypt')
require('dotenv').config()
const sgMail = require('@sendgrid/mail')


/* GET users listing. */
router.get('/',(req, res)=>{
  db.query('select * from `users`', (err, data)=>{
    res.json({
      data
    })
  })
})

//Token verification and send token data
router.get('/token', (req, res)=> {
  var token = req.headers['token']
  if (!token) return res.json({ success: false, err: 'No token provided.' })

  jwt.verify(token, process.env.SECRET, function (err, user) {
      if (err) return res.json({ success: false, err: 'Token Expire. Please Login again' })
      if (user) {
        res.send(user)
      }
  });
})

//Send mail to verify email
router.post('/forget-password',(req, res)=>{
  let email = req.body.Email

  const forgetPasswordTokenData = {
    Email: email,
    expireTime: Math.floor(Date.now() / 1000)
  }
  const forgetPasswordToken = jwt.sign(forgetPasswordTokenData, process.env.SECRET, { expiresIn: 3600 })

  db.query('UPDATE `users` SET `forgetPasswordToken`= ? WHERE users.email= ?',[forgetPasswordToken, email] , async (err, result)=>{
    if(err){
      res.json({
        success: false,
        error: err.message
      })
    }
    if(result){
      sgMail.setApiKey(process.env.SENDGRID_API_KEY)
      const mail = {
        to: email,
        from: 'ihtasham@sectem.com',
        subject: 'Forget Password Email',
        text: `Verify your Email to reset your password.
              Please copy and paste the address below to verify your account.
              http://localhost:5000/users/verifyEmailPassword?token=${forgetPasswordToken}`,
        html: `<strong>Hello!</strong>
                <p>Verify your Email to reset your password</p>
                <p>Please click on the link below to verify your account.</p>
                <a href="http://localhost:5000/users/verifyEmailPassword?token=${forgetPasswordToken}">Verify your account</a>`,
      }
      try{
        await sgMail.send(mail);
        res.json({
          success: true,
          msg:"Please check your email for verification."
        })
      }catch(error){
        res.send(error)
      }
    }
  })
})

//Verification of that token sent to reset password
router.get('/verifyEmailPassword', (req, res)=>{
  let reqToken = req.query.token
  db.query('SELECT * FROM `users` WHERE users.forgetPasswordToken = ?', [reqToken], (err1, data)=>{
    if(err1){
      res.json({
        success:false,
        error: err1.message
      })
    }
    if(data && data.length==1){
      jwt.verify(reqToken, process.env.SECRET, (err, user)=> {
        if (err) return res.json({ success: false, err: err.message })
        if (user) {
          // res.json(user)
          // if(user.expireTime >= user.exp){
          if(user.Email == data[0].email){
            res.json({
              success: true,
              mcg: "Email verified"
            })            
          }
          // else{
          //   res.json({
          //     success: false,
          //     msg: "Token Expires"
          //   })
          // }
          
        }
      })
    }
    if(data.length == 0){
      res.json({
        success:false,
        mcg: "No such user found"
      })
    }
  })
})

//Set new password
router.post('/reset-password', (req, res)=>{
  let email = req.body.Email
  let password = req.body.Password
  bcrypt.hash(password,10, (err, hash)=> {
    if(hash){
      db.query('UPDATE `users` SET `password`=? WHERE users.email = ?',[hash, email] ,(err, result)=>{
        if(err){
          res.json({
            success: false,
            error: err.message
          })
        }
        if(result){
          res.json({
            success:true,
            mcg: "Password Change Successfully"
          })
        }
      })
    }
  })
})

//Sing up new user and send mail to the user
router.post('/signup', (req, res)=> {
  let username = req.body.Username
  let email = req.body.Email
  let password = req.body.Password

  bcrypt.hash(password,10, (err, hash)=> {
    if(hash){
      // let expireTime= 3600 + Math.floor(Date.now() / 1000)
      const verificationTokenData = {
        Email: email,
        expireTime: Math.floor(Date.now() / 1000)
      }
      const varificationToken = jwt.sign(verificationTokenData, process.env.SECRET, { expiresIn: 3600 })

      
      db.query('SELECT * FROM `users` WHERE users.email=?',[email],(entryError, result)=>{
        if(entryError){
          res.json({
            success:false,
            error:entryError.message
          })
        }
        if(result.length == 1){
          res.json({
            success:false,
            error: `Your Email ${email} already registered.`
          })
        }
        if(result.length == 0){
          const values = [username, email, hash, varificationToken]
          db.query('INSERT INTO `users`(`username`, `email`, `password`, `verificationToken`) VALUES (?)',[values] , async (err, result)=>{
            if(err){
              res.json({
                success: false,
                error: err.message
              })
            }
            if(result){
              sgMail.setApiKey(process.env.SENDGRID_API_KEY)
              const mail = {
                to: email,
                from: 'ihtasham@sectem.com',
                subject: 'Verification Email',
                text: `Thanks for registering on our site.
                      PLease copy and paste the address below to verify your account.
                      http://localhost:5000/users/verify-email?token=${varificationToken}`,
                html: `<strong>Hello ${username}!</strong>
                        <p>Thanks for registering on our site.</p>
                        <p>Please click on the link below to verify your account.</p>
                        <a href="http://localhost:5000/users/verify-email?token=${varificationToken}">Verify your account</a>`,
              }
              try{
                await sgMail.send(mail);
                res.json({
                  success: true,
                  msg:"Thanks for registering with us. Please check your email for verification."
                })
              }catch(error){
                db.query('DELETE FROM `users` WHERE users.email= ?', [email],(err1, result)=>{
                  if(err1){
                    res.json({
                      success:false,
                      msg:err1.message
                    })
                  }
                  if(result){
                    res.json({
                      emailError: error,
                      mcg: 'There is an error signing you up. Please try again later.'
                    })
                    res.send(error)
                  }
                })
                
              }
            }
          })
        }
      })
    }
  })
})

//Verify email for sign up 
router.get('/verify-email', (req, res)=>{
  let reqToken = req.query.token
  db.query('SELECT * FROM `users` WHERE users.verificationToken = ?', [reqToken], (err1, data)=>{
    if(err1){
      res.json({
        success:false,
        error: err1.message
      })
    }
    if(data && data.length==1){
      if(data[0].verified == 0){
        jwt.verify(reqToken, process.env.SECRET, (err, user)=> {
          if (err) return res.json({ success: false, err: err.message })
          if (user) {
            // res.json(user)
            if(user.expireTime <= (Math.floor(Date.now() / 1000)+3600)){
              if(user.Email == data[0].email){
                db.query('UPDATE `users` SET `verified`=? WHERE users.email=?',[1, data[0].email], (errVerified, result)=>{
                  if(errVerified){
                    res.json({
                      success: false,
                      error: errVerified.message
                    })
                  }
                  if(result){
                    res.json({
                      success: true,
                      mcg: "Email verified"
                    })
                  }
                })
                
              }
            }else{
              res.json({
                success: false,
                msg: "Token Expires"
              })
            }
            
          }
        })
      }
      if(data[0].verified == 1){
        res.json({
          mcg:'Email Already verified'
        })
      }
    }
    if(data.length == 0){
      res.json({
        success:false,
        mcg: "No such user found"
      })
    }
    

  })
})

//Login and send token
router.post('/login', (req, res)=> {
  let email = req.body.Email
  let password = req.body.Password
    db.query('SELECT * FROM users WHERE email = ? LIMIT 1', [email], (err, data) => {
        if (err) {
            res.json({
                success: false,
                error: err.message
            })
        }
        if (data && data.length == 1) {
            bcrypt.compare(password, data[0].password, (bcryptErr, verified) => {
                if (verified) {
                  const user = {
                      success: true,
                      Id: data[0].id,
                      UserName: data[0].username,
                      Email: data[0].email
                  }

                  var accessTokenTime = new Date(Date.now() + (30 * 60 * 1000))
                  var refreshTokenTime = new Date(Date.now() + (60 * 60 * 1000))

                  const accessToken = jwt.sign(user, process.env.SECRET, { expiresIn: 1800 })
                  const refreshToken = jwt.sign(user, process.env.SECRET, { expiresIn: 3600 })

                  db.query('UPDATE `users` SET `accessToken`= ?,`refreshToken`= ? WHERE users.email= ?',[accessToken, refreshToken, email],(errToken , resultToken)=>{
                    if(errToken){
                      res.json({
                        success: false,
                        error: errToken.message
                      })
                    }
                    
                    if(resultToken){
                      res.json({
                        success: true,
                        AccesToken: {
                          token: accessToken,
                          expireIn: accessTokenTime
                        },
                        RefreshToken:{
                          token: refreshToken,
                          expireIn: refreshTokenTime
                        }

                      })
                    }
                  })

                }
                else {
                  res.json({
                    success: false,
                    error: 'Invalid Password'
                  })
                }
            })
        }
        else {
            res.json({
              success: false,
              error: 'User Not found. Try Again!'
            })
        }
    })
})

//Refresh both login tokens
router.post('/refreshTokens', (req, res)=>{
  // let accessToken = req.headers['token']
  let refreshToken = req.body.RefreshToken

  db.query('SELECT * FROM users WHERE refreshToken = ? LIMIT 1', [refreshToken], (err, data) => {
    if (err) {
        res.json({
            success: false,
            error: err.message
        })
    }
    if (data && data.length == 1) {
      const user = {
          success: true,
          Id: data[0].id,
          UserName: data[0].username,
          Email: data[0].email
      }

      var accessTokenTime = new Date(Date.now() + (30 * 60 * 1000))
      var refreshTokenTime = new Date(Date.now() + (60 * 60 * 1000))

      const accessToken = jwt.sign(user, process.env.SECRET, { expiresIn: 1800 })
      const refreshToken = jwt.sign(user, process.env.SECRET, { expiresIn: 3600 })

      db.query('UPDATE `users` SET `accessToken`= ?,`refreshToken`= ? WHERE users.email= ?',[accessToken, refreshToken, data[0].email],(errToken , resultToken)=>{
        if(errToken){
          res.json({
            success: false,
            error: errToken.message
          })
        }
        
        if(resultToken){
          res.json({
            success: true,
            AccesToken: {
              token: accessToken,
              expireIn: accessTokenTime
            },
            RefreshToken:{
              token: refreshToken,
              expireIn: refreshTokenTime
            }

          })
        }
      })

    }
    else {
      res.json({
        success: false,
        error: 'User Not found. Try Again!'
      })
    }
})


})


module.exports = router