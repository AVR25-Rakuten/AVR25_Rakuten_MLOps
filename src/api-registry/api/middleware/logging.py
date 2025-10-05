import logging
from datetime import datetime, UTC
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger = logging.getLogger("registry_nfq")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)

        start = datetime.now(UTC)
        logger.info("REQ %s %s", request.method, request.url)
        resp = await call_next(request)
        dur = (datetime.now(UTC) - start).total_seconds()
        logger.info("RES %s %s in %.3fs", resp.status_code, request.url.path, dur)
        return resp
