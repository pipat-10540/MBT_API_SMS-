// import { Router } from "express";
// import { welcome } from "../controllers/home.controller";

// class HomeRoutes {
//   router = Router();

//   constructor() {
//     this.intializeRoutes();
//   }

//   intializeRoutes() {
//     this.router.get("/", welcome);
//   }
// }

// export default new HomeRoutes().router;
import express from "express";
const router = express.Router();

router.get("/test-db", (req, res) => {
  res.send("✅ Route ทำงานแล้ว!");
});

export default router;
