const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const router = require('express').Router()
const User = require('./User.model')
const { registerValidation, loginValidation} = require('./validation')
const { valid } = require('@hapi/joi')
const verify = require('./verifyToken')

//Production Mode -> store to DB
let refreshTokens = []

//Register
router.post('/register', async (req, res) => {
    //validate 
    const {error} = registerValidation(req.body)
    if(error) return res.status(400).send(error.details[0].message)

    //Check if the user is already in DB
    const emailExist = await User.findOne({email: req.body.email})
    if(emailExist) return res.status(400).send('Email already exists')

    //Hash the password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(req.body.password, salt)


    //Create a new user
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    })
    try {
        const savedUser = await user.save()
        res.send({user: savedUser._id})
    } catch (err) {
        res.status(400).send(err)
    }
})

//Login
router.post('/login', async (req, res) => {
    //validate 
    const {error} = loginValidation(req.body)
    if(error) return res.status(400).send(error.details[0].message)
    
    //Check if the user exists
    const user = await User.findOne({email: req.body.email})
    if(!user) return res.status(400).send('Email not found') 
    
    //Password is correct
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if(!validPass) return res.status(400).send('invalid password')

    //Create and assign token
    const accessToken = generateAccessToken(user._id)
    const refreshToken = generateRefreshToken(user._id)
    refreshTokens.push(refreshToken)
    res.header('auth-token', accessToken).status(200).send({accessToken, refreshToken})
})

//Get new Access Token
router.post('/token', async (req, res) => {
    const refreshToken = req.body.token
    if(refreshToken == null) return res.status(401).send('no refreshToken specified')
    if(!refreshTokens.includes(refreshToken)) return res.status(403).send('unknown refreshToken')
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, userid) => {
        if(err) return res.status(403)
        const accessToken = generateAccessToken({userid})
        res.json({accessToken})
    })
})

//Logout
router.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

//Protected route
router.get('/protected', verify, (req, res) => {
    res.json({posts: {title: 'my post', description: 'my description'}})
})

//Generate Access Token
function generateAccessToken(userid){
    return jwt.sign({_id: userid}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '35s'})
}

//Generate Refresh Token
function generateRefreshToken(userid){
    return jwt.sign({_id: userid}, process.env.REFRESH_TOKEN_SECRET)
}


module.exports = router