const express = require('express');
const router = express.Router();
const { check } = require('express-validator');
const userController = require('../controllers/userController');

router.post(
  '/',
  [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Add a valid email').isEmail(),
    check('password', 'The password must be at least 6 characters').isLength({
      min: 6,
    }),
  ],
  userController.createUser
);

module.exports = router;
