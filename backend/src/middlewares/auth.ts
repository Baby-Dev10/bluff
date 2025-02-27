import jwt from "jsonwebtoken";
import { Request, Response, NextFunction, RequestHandler } from "express";

interface AuthRequest extends Request {
  user?: { userId: string };
}

export const auth: RequestHandler = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = req.header("Authorization")?.split(" ")[1];

    if (!token) {
      res.status(401).json({ message: "Access denied. No token provided." });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as {
      userId: string;
    };

    req.user = { userId: decoded.userId };

    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token." });
    return;
  }
};
