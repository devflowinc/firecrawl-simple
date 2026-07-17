import { Request, Response } from "express";

import { Logger } from "../../../lib/logger";
import { getScrapeQueue } from "../../../services/queue-service";

// Use this as a "health check" that way we dont destroy the server
export async function queuesController(req: Request, res: Response) {
  try {
    const scrapeQueue = getScrapeQueue();

    const [webScraperActive] = await Promise.all([
      scrapeQueue.getActiveCount(),
    ]);

    const noActiveJobs = webScraperActive === 0;
    // 200 if no active jobs, 503 if there are active jobs
    return res.status(noActiveJobs ? 200 : 500).json({
      webScraperActive,
      noActiveJobs,
    });
  } catch (error) {
    Logger.error(error);
    return res.status(500).json({ error: error.message });
  }
}
