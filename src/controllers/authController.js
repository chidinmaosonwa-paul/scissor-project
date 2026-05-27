import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { z } from 'zod'
import sql from '../config/db.js'

const signupSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters.'),
  email: z.string().email('Please enter a valid email address.'),
  password: z.string().min(8, 'Password must be at least 8 characters.'),
})

const loginSchema = z.object({
  email: z.string().email('Please enter a valid email address.'),
  password: z.string().min(1, 'Password is required.'),
})

export async function signup(req, res, next) {
  try {
    const result = signupSchema.safeParse(req.body)
    if (!result.success) {
      const error = new Error(result.error.errors[0].message)
      error.status = 400
      return next(error)
    }

    const { username, email, password } = result.data

    const existingEmail = await sql`
      SELECT id FROM users WHERE email = ${email} LIMIT 1
    `
    if (existingEmail.length > 0) {
      const error = new Error('An account with this email already exists.')
      error.status = 409
      return next(error)
    }

    const existingUsername = await sql`
      SELECT id FROM users WHERE username = ${username} LIMIT 1
    `
    if (existingUsername.length > 0) {
      const error = new Error('This username is already taken.')
      error.status = 409
      return next(error)
    }

    const hashedPassword = await bcrypt.hash(password, 12)

    const [user] = await sql`
      INSERT INTO users (username, email, password)
      VALUES (${username}, ${email}, ${hashedPassword})
      RETURNING id, username, email
    `

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    res.status(201).json({ status: 'success', message: 'Account created.', token })
  } catch (err) {
    next(err)
  }
}

export async function login(req, res, next) {
  try {
    const result = loginSchema.safeParse(req.body)
    if (!result.success) {
      const error = new Error(result.error.errors[0].message)
      error.status = 400
      return next(error)
    }

    const { email, password } = result.data

    const [user] = await sql`
      SELECT * FROM users WHERE email = ${email} LIMIT 1
    `

    if (!user) {
      const error = new Error('Invalid email or password.')
      error.status = 401
      return next(error)
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      const error = new Error('Invalid email or password.')
      error.status = 401
      return next(error)
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    res.status(200).json({ status: 'success', message: 'Logged in.', token })
  } catch (err) {
    next(err)
  }
}

export async function logout(req, res) {
  res.clearCookie('token')
  res.status(200).json({ status: 'success', message: 'Logged out.' })
}