import express from 'express'
import {
  createUrl,
  getUserUrls,
  deleteUrl,
  toggleUrl,
  getAnalytics,
} from '../controllers/urlController.js'
import auth from '../middleware/auth.js'
import { urlLimiter } from '../middleware/rateLimiter.js'

const router = express.Router()

router.get('/', auth, getUserUrls)
router.post('/', auth, urlLimiter, createUrl)
router.delete('/:id', auth, deleteUrl)
router.patch('/:id/toggle', auth, toggleUrl)
router.get('/:id/analytics', auth, getAnalytics)

export default router