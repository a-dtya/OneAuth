const express = require('express')
const crypto = require("node:crypto")
if(!globalThis.crypto){
    globalThis.crypto = crypto
}
const {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions, verifyAuthenticationResponse} = require('@simplewebauthn/server')
const PORT = 3000
const app = express()

const userStore ={}
const challengeStore ={}



app.use(express.static('./public'))
app.use(express.json())

app.post('/register',(req,res)=>{
    const {username,password} = req.body
    const id = `user_${Date.now()}`
    const user = {
        id,
        username,
        password
    }

    userStore[id]=user
    return res.json({id})
})

app.post('/register-challenge',async(req,res)=>{
    const {userId} = req.body
    if(!userStore[userId]) return res.json({error:'user not registered'})
    const user = userStore[userId]
    const challengePayload = await generateRegistrationOptions({
        
        rpName: 'My local machine',
        rpID: 'localhost',
        userName: user.username,
    })

    challengeStore[userId] = challengePayload.challenge
    
    return res.json({options: challengePayload})
})

app.post('/register-verify',async(req,res)=>{
    const {userId, cred} = req.body
    if(!userStore[userId]) return res.json({error:'user not registered'})
    const user = userStore[userId]
    const challenge = challengeStore[userId]
    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: "http://localhost:3000",
        expectedRPID: "localhost",
        response: cred
    })
    if(!verificationResult.verified) return res.json({error: "could not verify user"})
    userStore[userId].passkey = verificationResult.registrationInfo
    console.log(userStore[userId].passkey)
    return res.json({verified: true})
})

app.post('/login-challenge',async(req,res)=>{
    const {userId} = req.body
    if(!userStore[userId]) return res.json({error:'user not registered'})
    const opts = await generateAuthenticationOptions({
        rpID:"localhost"
})
    challengeStore[userId] = opts.challenge

    return res.json({options: opts})
})

app.post('/login-verify',async(req,res)=>{
    const {userId,cred}=req.body
    if(!userStore[userId]) return res.json({error:'user not registered'})
    const user = userStore[userId]
    console.log(userStore[userId])
    const challenge = challengeStore[userId]
    try {
        const result = await verifyAuthenticationResponse({
            response:cred,
            expectedChallenge: challenge,
            expectedOrigin: 'http://localhost:3000',
            expectedRPID:'localhost',
            authenticator: user.passkey
        })
        if(!result.verified) return res.json({error: 'verification failed at login'})
            // login the user, create session , cookies etc
        return res.json({success: true, userId})
    } catch (error) {
        console.log("eroor")
    }
    
    
    
})
app.listen(PORT, ()=>{
    console.log("Server started in port 3000")
})

