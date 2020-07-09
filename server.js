require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose')

//Import routes
const authRoute = require('./routes')

//Connect to DB
mongoose.connect(
    process.env.DB_CONNECT,
    { useNewUrlParser: true, useUnifiedTopology: true },
    () => console.log('connected to db'))


//Middlewares
app.use(express.json())

//Route Middlewares
app.use('/api/', authRoute)


app.listen(3000, () => console.log('server up and running'))