import { UnauthorizedError } from "../errors/UnauthorizedError.js";

import { verifyToken } from "../utils/token/token.js";
import { ForbiddenError } from "../errors/ForbiddenError.js";

export const authMiddleware = (authRole) => {
  return async (req, res, next) => {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      return next(
        new UnauthorizedError("authorization header must be provided")
      );
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      return next(new UnauthorizedError("token not provided"));
    }

    try {
      const payload = verifyToken(token);

      if (Date.now() > payload.expiresIn) {
        next(new UnauthorizedError("expired token"));
      }

      if (!authRole.includes(payload.role)) {
        next(new ForbiddenError("you don't have permission"));
      }

      console.log(payload);

      req.user = payload;

      next();
    } catch (err) {
      throw new UnauthorizedError("invalid token");
    }
  };
};
