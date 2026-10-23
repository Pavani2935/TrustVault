"""Uniform JSON errors. Internal details never reach the client."""
from __future__ import annotations

import logging

from flask import g, jsonify
from werkzeug.exceptions import HTTPException

from .validation import ValidationError

log = logging.getLogger("trustvault")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, field: str | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.field = status, code, message, field


def not_found() -> ApiError:
    # One message for "does not exist" and "exists but you have no access":
    # the response must not reveal which one is true.
    return ApiError(404, "not_found", "Not found.")


def _payload(status: int, code: str, message: str, field: str | None = None):
    body = {"error": {"code": code, "message": message, "request_id": getattr(g, "request_id", None)}}
    if field:
        body["error"]["field"] = field
    return jsonify(body), status


def register(app) -> None:
    @app.errorhandler(ApiError)
    def _api_error(err: ApiError):
        return _payload(err.status, err.code, err.message, err.field)

    @app.errorhandler(ValidationError)
    def _validation(err: ValidationError):
        return _payload(400, "invalid", str(err), err.field)

    @app.errorhandler(HTTPException)
    def _http(err: HTTPException):
        code = {404: "not_found", 405: "method_not_allowed", 413: "too_large", 400: "bad_request"}.get(err.code, "http_error")
        message = "Not found." if err.code == 404 else (err.description or err.name)
        if err.code == 413:
            message = "Upload exceeds the size limit."
        return _payload(err.code or 500, code, message)

    @app.errorhandler(Exception)
    def _unexpected(err: Exception):
        log.exception("unhandled error (request_id=%s)", getattr(g, "request_id", None))
        return _payload(500, "server_error", "Something went wrong. The error was logged.")
