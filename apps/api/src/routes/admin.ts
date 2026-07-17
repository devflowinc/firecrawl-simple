import express from "express";
import { redisHealthController } from "../controllers/v0/admin/redis-health";
import { queuesController } from "../controllers/v0/admin/queue";

export const adminRouter = express.Router();

adminRouter.get(
  `/admin/${process.env.BULL_AUTH_KEY}/redis-health`,
  redisHealthController
);

adminRouter.get(`/admin/${process.env.BULL_AUTH_KEY}/queues`, queuesController);
