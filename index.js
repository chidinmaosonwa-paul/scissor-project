import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import dotenv from 'dotenv'
import path from 'path'
import { fileURLToPath } from 'url'
import cookieParser from 'cookie-parser'

import connectDB from './src/config/db.js'
import authRoutes from './src/routes/auth.js'
import urlRoutes from './src/routes/url.js'
import userRoutes from './src/routes/user.js'
import errorHandler from './src/middleware/errorHandler.js'
import { redirectUrl, verifyPassword } from './src/controllers/urlController.js'

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.set('trust proxy', 1)
const PORT = process.env.PORT || 5000

connectDB()

app.use(helmet({ contentSecurityPolicy: false }))
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || [],
  credentials: true,
}))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'src/public'), { maxAge: '1d' }))

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'src/views'))

app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }))

app.use('/api/auth', authRoutes)
app.use('/api/urls', urlRoutes)
app.use('/api/user', userRoutes)

app.get('/', (req, res) => res.render('pages/index', { title: 'Shorten URLs' }))
app.get('/login', (req, res) => res.render('pages/login', { title: 'Log In' }))
app.get('/signup', (req, res) => res.render('pages/signup', { title: 'Sign Up' }))
app.get('/dashboard', (req, res) => res.render('pages/dashboard', { title: 'Dashboard' }))
app.get('/dashboard/analytics/:id', (req, res) => res.render('pages/analytics', { title: 'Analytics' }))

app.get('/:shortCode', redirectUrl)
app.post('/:shortCode/verify', verifyPassword)

app.use(errorHandler)

app.listen(PORT, () => console.log(`Server running on port ${PORT}`))