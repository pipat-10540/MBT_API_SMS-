import { Router } from "express";
import UserController from "../controllers/user.controller";

class UserRoutes {
  router = Router();
  controller = new UserController();

  constructor() {
    this.intializeRoutes();
  }
  intializeRoutes() {
    this.router.post("/register", this.controller.registerUser);
    this.router.post("/login", this.controller.loginUser);
    this.router.post("/forgot-password", this.controller.forgotPassword);
    this.router.post("/reset-password", this.controller.resetPassword);
    this.router.post("/send-sms", this.controller.sendSMS);
    this.router.get("/contactGetUser/:id", this.controller.contactGetUser);
    this.router.post("/contactUser", this.controller.contactUser);
    this.router.put("/contactUpdateUser/:id", this.controller.contactUpdateUser);
    this.router.get("/sms-status", this.controller.handleSmsWebhook);
  }
}
export default new UserRoutes().router;
