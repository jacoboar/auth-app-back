const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
  const token = req.header('x-auth-token');

  if (!token) {
    return res.status(401).json({ msg: 'No token, invalid permission' });
  }

  try {
    const encryp = jwt.verify(token, process.env.JWT_SECRET);
    req.user = encryp.user;
    next();
  } catch (error) {
    res.status(401).json({ msg: 'Invalid token' });
  }
};
