import sql from '../config/db.js'

export async function getProfile(req, res, next) {
  try {
    const [user] = await sql`
      SELECT id, username, email, created_at FROM users WHERE id = ${req.user.id} LIMIT 1
    `
    if (!user) {
      const error = new Error('User not found.')
      error.status = 404
      return next(error)
    }
    res.status(200).json({ status: 'success', data: user })
  } catch (err) {
    next(err)
  }
}