import jwt from "jsonwebtoken";
import { handleError } from "./error.js";

export const verifyToken = (req, res, next) => {
  //accessing token from cookie
  const token = req.cookies.access_token;

  if (!token) return next(handleError(401, "You are not authenticated"));
  //matching token with user logged in
  jwt.verify(token, process.env.JWT, (err, user) => {
    if (err) return next(createError(403, "Token is invalid"));
    req.user = user;
    next();
  });
};
