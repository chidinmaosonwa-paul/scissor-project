import crypto from 'crypto'
import { nanoid } from 'nanoid'
import QRCode from 'qrcode'
import bcrypt from 'bcryptjs'
import { z } from 'zod'
import sql from '../config/db.js'

const createUrlSchema = z.object({
  originalUrl: z.string().url('Please enter a valid URL starting with http or https.'),
  customAlias: z
    .string()
    .regex(/^[a-zA-Z0-9_-]{3,20}$/, 'Alias must be 3 to 20 alphanumeric characters.')
    .optional()
    .or(z.literal('')),
  password: z.string().optional().or(z.literal('')),
  expiresAt: z.string().optional().or(z.literal('')),
})

export async function createUrl(req, res, next) {
  try {
    const result = createUrlSchema.safeParse(req.body)
    if (!result.success) {
      const error = new Error(result.error.errors[0].message)
      error.status = 400
      return next(error)
    }

    const { originalUrl, customAlias, password, expiresAt } = result.data
    const shortCode = customAlias || nanoid(6)

    if (customAlias) {
      const existing = await sql`
        SELECT id FROM urls WHERE short_code = ${customAlias} LIMIT 1
      `
      if (existing.length > 0) {
        const error = new Error('This custom alias is already in use.')
        error.status = 409
        return next(error)
      }
    }

    const shortUrl = `${process.env.BASE_URL}/${shortCode}`
    const qrCode = await QRCode.toDataURL(shortUrl)

    let hashedPassword = null
    if (password && password.trim() !== '') {
      hashedPassword = await bcrypt.hash(password, 12)
    }

    let expiry = null
    if (expiresAt && expiresAt.trim() !== '') {
      expiry = new Date(expiresAt)
    }

    const [url] = await sql`
      INSERT INTO urls (original_url, short_code, custom_alias, qr_code, user_id, password, expires_at)
      VALUES (${originalUrl}, ${shortCode}, ${customAlias || null}, ${qrCode}, ${req.user.id}, ${hashedPassword}, ${expiry})
      RETURNING *
    `

    res.status(201).json({ status: 'success', data: url })
  } catch (err) {
    next(err)
  }
}

export async function getUserUrls(req, res, next) {
  try {
    const urls = await sql`
      SELECT * FROM urls WHERE user_id = ${req.user.id} ORDER BY created_at DESC
    `
    res.status(200).json({ status: 'success', data: urls })
  } catch (err) {
    next(err)
  }
}

export async function deleteUrl(req, res, next) {
  try {
    const [url] = await sql`
      SELECT * FROM urls WHERE id = ${req.params.id} LIMIT 1
    `

    if (!url) {
      const error = new Error('Link not found.')
      error.status = 404
      return next(error)
    }

    if (url.user_id !== req.user.id) {
      const error = new Error('You do not have permission to delete this link.')
      error.status = 403
      return next(error)
    }

    await sql`DELETE FROM urls WHERE id = ${req.params.id}`

    res.status(200).json({ status: 'success', message: 'Link deleted.' })
  } catch (err) {
    next(err)
  }
}

export async function toggleUrl(req, res, next) {
  try {
    const [url] = await sql`
      SELECT * FROM urls WHERE id = ${req.params.id} LIMIT 1
    `

    if (!url) {
      const error = new Error('Link not found.')
      error.status = 404
      return next(error)
    }

    if (url.user_id !== req.user.id) {
      const error = new Error('You do not have permission to update this link.')
      error.status = 403
      return next(error)
    }

    const [updated] = await sql`
      UPDATE urls SET is_active = ${!url.is_active}
      WHERE id = ${req.params.id}
      RETURNING is_active
    `

    res.status(200).json({ status: 'success', data: { isActive: updated.is_active } })
  } catch (err) {
    next(err)
  }
}

export async function redirectUrl(req, res, next) {
  try {
    const { shortCode } = req.params
    const [url] = await sql`
      SELECT * FROM urls WHERE short_code = ${shortCode} LIMIT 1
    `

    if (!url) {
      return res.status(404).render('pages/404', {
        title: 'Link Not Found',
        message: 'This link does not exist or has been removed.',
      })
    }

    if (!url.is_active) {
      return res.status(410).render('pages/404', {
        title: 'Link Inactive',
        message: 'This link has been deactivated.',
      })
    }

    if (url.expires_at && new Date() > new Date(url.expires_at)) {
      return res.status(410).render('pages/404', {
        title: 'Link Expired',
        message: 'This link has expired and is no longer available.',
      })
    }

    if (url.password) {
      return res.render('pages/password', {
        title: 'Protected Link',
        shortCode,
        error: null,
      })
    }

    const ipHash = crypto
      .createHash('sha256')
      .update(req.ip || '')
      .digest('hex')

    await sql`
      INSERT INTO clicks (url_id, user_agent, referrer, ip_hash)
      VALUES (${url.id}, ${req.headers['user-agent'] || ''}, ${req.headers['referer'] || 'Direct'}, ${ipHash})
    `

    await sql`
      UPDATE urls SET clicks = clicks + 1 WHERE id = ${url.id}
    `

    res.redirect(url.original_url)
  } catch (err) {
    next(err)
  }
}

export async function verifyPassword(req, res, next) {
  try {
    const { shortCode } = req.params
    const { password } = req.body

    const [url] = await sql`
      SELECT * FROM urls WHERE short_code = ${shortCode} LIMIT 1
    `

    if (!url) {
      const error = new Error('Link not found.')
      error.status = 404
      return next(error)
    }

    const isMatch = await bcrypt.compare(password, url.password)

    if (!isMatch) {
      return res.render('pages/password', {
        title: 'Protected Link',
        shortCode,
        error: 'Incorrect password. Please try again.',
      })
    }

    const ipHash = crypto
      .createHash('sha256')
      .update(req.ip || '')
      .digest('hex')

    await sql`
      INSERT INTO clicks (url_id, user_agent, referrer, ip_hash)
      VALUES (${url.id}, ${req.headers['user-agent'] || ''}, ${req.headers['referer'] || 'Direct'}, ${ipHash})
    `

    await sql`
      UPDATE urls SET clicks = clicks + 1 WHERE id = ${url.id}
    `

    res.redirect(url.original_url)
  } catch (err) {
    next(err)
  }
}

export async function getAnalytics(req, res, next) {
  try {
    const [url] = await sql`
      SELECT * FROM urls WHERE id = ${req.params.id} LIMIT 1
    `

    if (!url) {
      const error = new Error('Link not found.')
      error.status = 404
      return next(error)
    }

    if (url.user_id !== req.user.id) {
      const error = new Error('You do not have permission to view these analytics.')
      error.status = 403
      return next(error)
    }

    const clicks = await sql`
      SELECT * FROM clicks WHERE url_id = ${url.id} ORDER BY timestamp DESC
    `

    const last7Days = Array.from({ length: 7 }, (_, i) => {
      const date = new Date()
      date.setDate(date.getDate() - (6 - i))
      return date.toISOString().split('T')[0]
    })

    const clicksByDay = last7Days.map(day => ({
      date: day,
      count: clicks.filter(c => c.timestamp.toISOString().split('T')[0] === day).length,
    }))

    const referrerMap = {}
    clicks.forEach(c => {
      const ref = c.referrer || 'Direct'
      referrerMap[ref] = (referrerMap[ref] || 0) + 1
    })

    const topReferrers = Object.entries(referrerMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([referrer, count]) => ({ referrer, count }))

    res.status(200).json({
      status: 'success',
      data: {
        url,
        totalClicks: clicks.length,
        clicksByDay,
        topReferrers,
      },
    })
  } catch (err) {
    next(err)
  }
}