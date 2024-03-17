const User = require("../models/user");
// const {emailValidation, passValidation}  = require("../middleware/validation");

const link = "https://kappa.lol/VMimi";
const messanger = "https://kappa.lol/iSONv";
const logger = require("../logger/index");
const winston = require("winston");
const jwt = require("jsonwebtoken");
require("dotenv").config();
exports.form = (req, res) => {
  res.render("registerForm", { errors: {}, link: link, messanger: messanger });
};

exports.submit = (req, res, next) => {
  const { name, email, password } = req.body;
  User.findByEmail(email, (error, user) => {
    if (error) return next(error);
    if (user) {
      logger.info("Такой пользователь в базе уже существует.");
      res.redirect("/");
    } else {
      User.create(req.body, (err) => {
        if (err) return next(err);
        req.session.userEmail = email;
        req.session.userName = name;

        const token = jwt.sign(
          {
            name: req.body.name,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: 60 * 60,
          }
        );
        res.cookie("jwt", token, {
          httpOnly: true,
          maxAge: 60 * 60,
        });
        console.log("Токен подготовлен: " + token);
        // Добавляем токен в ответ

        logger.info("Токен подготовлен: " + token);
        res.redirect("/");
      });
    }
  });
};
