import express from "express"
import mongoose from "mongoose"
import dotenv from "dotenv"
import cors from 'cors'

import authRoute from './routes/auth.js'

const app = express()
dotenv.config()

const PORT = process.env.PORT || 3001
const DB_USER = process.env.DB_USER
const DB_PASSWORD = process.env.DB_PASSWORD
const DB_NAME = process.env.DB_NAME

app.use(cors())
app.use(express.json())

app.use('/api/auth', authRoute)

app.get('/', (req, res) => {
  res.json({ message: "Everything is fine" })
})

async function start() {
  try {
    await mongoose.connect(
      `mongodb+srv://${DB_USER}:${DB_PASSWORD}@cluster0.ikdqum1.mongodb.net/${DB_NAME}?retryWrites=true&w=majority`
    )
     app.listen(PORT,()=> console.log(`Server started on port: ${PORT}`))
  } catch (error) {
    console.log(error)
  }
}

start()
