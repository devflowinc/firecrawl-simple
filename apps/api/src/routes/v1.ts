import express, { NextFunction, Response } from "express";
import { RateLimiterMode } from "../types";
import { authenticateUser } from "../controllers/auth";
import { mapController } from "../controllers/v1/map";
import { RequestWithMaybeAuth } from "../controllers/v1/types";
import { livenessController } from "../controllers/v1/liveness";
import { readinessController } from "../controllers/v1/readiness";
import expressWs from "express-ws";

export function authMiddleware(
  rateLimiterMode: RateLimiterMode
): (req: RequestWithMaybeAuth, res: Response, next: NextFunction) => void {
  return (req, res, next) => {
    (async () => {
      const { success, team_id, error, status, plan } = await authenticateUser(
        req,
        res,
        rateLimiterMode
      );

      if (!success) {
        if (!res.headersSent) {
          return res.status(status).json({ success: false, error });
        }
      }

      req.auth = { team_id, plan };
      next();
    })().catch((err) => next(err));
  };
}

function wrap(
  controller: (req: express.Request, res: Response) => Promise<any>
): (req: express.Request, res: Response, next: NextFunction) => any {
  return (req, res, next) => {
    controller(req, res).catch((err) => next(err));
  };
}

expressWs(express());

export const v1Router = express.Router();

v1Router.post("/map", authMiddleware(RateLimiterMode.Map), wrap(mapController));

// Health/Probe routes
v1Router.get("/health/liveness", livenessController);
v1Router.get("/health/readiness", readinessController);
