function errorHandler(err, req, res, next) {
  const status = err.status || 500
  const message =
    status < 500
      ? err.message
      : 'Something went wrong. Please try again.'

  console.error(`[${new Date().toISOString()}] ${status} - ${err.message}`)

  if (req.accepts('html')) {
    return res.status(status).render('pages/404', { title: 'Error', message })
  }

  res.status(status).json({ status: 'error', message })
}

export default errorHandler