import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { handleError } from "../error.js";
// cookie parser->for express server to read the cookies
// next->middleware
export const signup = async (req, res, next) => {
  try {
    //hashing the password
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);
    // saving data to mongodb
    const newUser = new User({ ...req.body, password: hash });

    await newUser.save();
    //creating jwt token cookie
    const token = jwt.sign({ id: newUser._id }, process.env.JWT);

    const { password, ...othersData } = newUser._doc;
    res
      .cookie("access_token", token, {
        httpOnly: true,
      })
      .status(200)
      .json(othersData);
  } catch (err) {
    next(err);
  }
};

export const signin = async (req, res, next) => {
  try {
    const user = await User.findOne({ username: req.body.username });

    if (!user) return next(handleError(404, "User not found"));
    //matching password using bcrypt
    const isCorrect = await bcrypt.compare(req.body.password, user.password);

    if (!isCorrect) return next(handleError(400, "Wrong password"));
    //creating token if password matches
    const token = jwt.sign({ id: user._id }, process.env.JWT);
    const { password, ...othersData } = user._doc;

    res
      .cookie("access_token", token, { httpOnly: true })
      .status(200)
      .json(othersData);
  } catch (err) {
    next(err);
  }
};
