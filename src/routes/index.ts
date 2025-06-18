import { Application } from "express";
import homeRoutes from "./home.routes";
import tutorialRoutes from "./tutorial.routes";
import userRoutes from "./user.routes";

export default class Routes {
  constructor(app: Application) {
    app.use("/api/home", homeRoutes);
    app.use("/api/tutorials", tutorialRoutes);
    app.use("/api/users", userRoutes);
  }
}
