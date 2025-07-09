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
    this.router.put("/contactUpdateUser", this.controller.contactUpdateUser);
    this.router.post("/contactDelete", this.controller.contactDelete);
    this.router.post("/contactgroups", this.controller.contactgroups);
    this.router.get("/contactGetgroups/:id", this.controller.contactGetgroups);
    this.router.put(
      "/contactUpdategroups",
      this.controller.contactUpdategroups
    );
    this.router.post(
      "/contactDeletegroups",
      this.controller.contactDeletegroups
    );
    this.router.get("/sms-status", this.controller.handleSmsWebhook);
  }
}
export default new UserRoutes().router;
