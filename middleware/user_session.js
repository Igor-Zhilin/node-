const User = require("../models/user");

module.exports = function (req, res, next) {
  if (req.session.userEmail) {
    User.findByEmail(req.session.userEmail, (error, userData) => {
      if (error) return next(error);
      if (userData) {
        req.user = res.locals.user = userData;
        res.locals.admin = userData.isAdmin === 1 ? true : false;
      }
    });
  }
  if (req.session.passport) {
    res.locals.user = req.session.passport.user;
  }
  return next();
};