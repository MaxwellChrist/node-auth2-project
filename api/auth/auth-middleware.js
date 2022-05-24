const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken');
const Users = require('../users/users-model')

const restricted = async (req, res, next) => {
  if (req.headers.authorization == null) {
    next({ status: 401, message: "Token required" })
    return
  }
  try {
    req.decodedJwt = await jwt.verify(req.headers.authorization, JWT_SECRET);
    next()
  } catch(err) {
    next({ status: 401, message: "Token invalid" });
    return;
  }
}

const only = role_name => (req, res, next) => {
  if(req.decodedJwt == null) {
    next({ message: 'internal server error!' });
    return;
  }

  if (role_name != req.decodedJwt.role_name) {
    next({ status: 403, message: "This is not for you" })
    return
  }
  next()
}

const checkUsernameExists = async (req, res, next) => {
  let {username} = req.body;
  let result = await Users.findBy({username})
  if (result.length > 0) {
    next()
  } else {
    next({ status: 401, message: "Invalid credentials" })
  }
}

const validateRoleName = (req, res, next) => {
  if (req.body.role_name == null || req.body.role_name.trim() ===  "") {
    req.body.role_name = "student";
  } else {
    req.body.role_name = req.body.role_name.trim()
  } 
  if (req.body.role_name === "admin") {
    next({ status: 422, message: "Role name can not be admin" });
    return
  } 
  if (req.body.role_name.trim().length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" });
    return
  } 
  next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}