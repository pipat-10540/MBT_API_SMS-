import express from "express";
import { registerUser, loginUser } from "../controllers/user.controller";
import { forgotPassword } from "../controllers/password.controller";
import { resetPassword } from "../controllers/reset.controller";
import { sendSMS } from "../controllers/sms.controller";
import { handleSmsWebhook } from "../controllers/thaibulk.controller";

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);
router.post("/send-sms", sendSMS);
router.get("/sms-status", handleSmsWebhook);

export default router;
