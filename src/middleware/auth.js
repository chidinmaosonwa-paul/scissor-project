import jwt from 'jsonwebtoken'

function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      const err = new Error('Authentication required.')
      err.status = 401
      return next(err)
    }

    const token = authHeader.split(' ')[1]
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = decoded
    next()
  } catch (err) {
    const error = new Error('Invalid or expired session. Please log in again.')
    error.status = 401
    next(error)
  }
}

export default authMiddleware