import express from "express";
import { registerUser, loginUser } from "../controllers/user.controller";
import {
  forgotPassword,
  resetPassword,
} from "../controllers/password.controller";

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

export default router;
