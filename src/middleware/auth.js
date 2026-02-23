function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/admin/login');
  }

  return next();
}

module.exports = {
  requireAuth
};
