import os
from datetime import datetime, timedelta

import jwt
from dotenv import load_dotenv
from flask import jsonify, make_response

load_dotenv()


class TokensHandler:
    @classmethod
    def createAccessToken(cls, data, expires_delta):
        to_encode = data.copy()
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire, "token_type": "access"})
        JWT_SECRET = os.getenv("JWT_SECRET")
        JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
        if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
            raise Exception("TokensHandler :: createAccessToken :: Env vars not found")
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET, JWT_ALGORITHM)
        return encoded_jwt

    @classmethod
    def createRefreshToken(cls, data, expires_delta):
        to_encode = data.copy()
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire, "token_type": "refresh"})
        JWT_SECRET = os.getenv("JWT_SECRET")
        JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
        if (JWT_SECRET is None) or (JWT_ALGORITHM is None):
            raise Exception("TokensHandler :: createRefreshToken :: Env vars not found")
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return encoded_jwt

    @classmethod
    def refreshTokensIfNeeded(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        response = make_response()  # Prepare an empty response

        if refresh_token:
            try:
                JWT_SECRET = os.getenv("JWT_SECRET")
                JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
                ACCESS_TOKEN_EXPIRES_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES")
                REFRESH_TOKEN_EXPIRES_DAYS = os.getenv("REFRESH_TOKEN_EXPIRES_DAYS")
                if (
                    (JWT_SECRET is None)
                    or (JWT_ALGORITHM is None)
                    or (ACCESS_TOKEN_EXPIRES_MINUTES is None)
                    or (REFRESH_TOKEN_EXPIRES_DAYS is None)
                ):
                    raise Exception(
                        "TokensHandler :: refreshTokensIfNeeded :: Env vars not found"
                    )
                payload = jwt.decode(
                    refresh_token,
                    JWT_SECRET,
                    algorithms=[JWT_ALGORITHM],
                    options={"verify_exp": True},
                )
                if payload["token_type"] != "refresh":
                    # The token is not a refresh token
                    return response  # Return the original response without modification

                user_id = payload["user_id"]
                # Generate a new access token
                new_access_token = cls.createRefreshToken(
                    data={"user_id": user_id},
                    expires_delta=timedelta(
                        minutes=float(ACCESS_TOKEN_EXPIRES_MINUTES)
                    ),
                )
                # Optionally, generate a new refresh token here as well
                new_refresh_token = cls.createRefreshToken(
                    data={"user_id": user_id},
                    expires_delta=timedelta(days=float(REFRESH_TOKEN_EXPIRES_DAYS)),
                )
                # Set the new access token in the response cookies
                response.set_cookie(
                    "refresh_token",
                    new_refresh_token,
                    secure=True,
                    httponly=True,
                    samesite="Strict",
                    max_age=60 * 60 * 24,
                )
                # Optionally, set the new refresh token in the response cookies

                return response  # Return the response with the new tokens set
            except jwt.PyJWTError:
                # Refresh token is invalid or expired
                pass  # Do nothing, just return the original response

        return response  # Return the original response if no refresh token or if any error occurs

    @classmethod
    def checkAccessAndRefreshTokens(cls, request):
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")

        if access_token:
            try:
                JWT_SECRET = os.getenv("JWT_SECRET")
                JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
                ACCESS_TOKEN_EXPIRES_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES")
                REFRESH_TOKEN_EXPIRES_DAYS = os.getenv("REFRESH_TOKEN_EXPIRES_DAYS")
                if (
                    (JWT_SECRET is None)
                    or (JWT_ALGORITHM is None)
                    or (ACCESS_TOKEN_EXPIRES_MINUTES is None)
                    or (REFRESH_TOKEN_EXPIRES_DAYS is None)
                ):
                    raise Exception(
                        "TokensHandler :: refreshTokensIfNeeded :: Env vars not found"
                    )
                payload = jwt.decode(
                    access_token, JWT_SECRET, algorithms=[JWT_ALGORITHM]
                )
                # Access token is valid, return user_id (or other user details) from payload
                return {"user_id": payload["user_id"]}, None
            except jwt.ExpiredSignatureError:
                # Access token is expired; attempt to use the refresh token
                pass
            except jwt.PyJWTError:
                # Access token is invalid
                return None, jsonify({"error": "Invalid access token"}), 401

        if refresh_token:
            try:
                JWT_SECRET = os.getenv("JWT_SECRET")
                JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
                ACCESS_TOKEN_EXPIRES_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES")
                REFRESH_TOKEN_EXPIRES_DAYS = os.getenv("REFRESH_TOKEN_EXPIRES_DAYS")
                if (
                    (JWT_SECRET is None)
                    or (JWT_ALGORITHM is None)
                    or (ACCESS_TOKEN_EXPIRES_MINUTES is None)
                    or (REFRESH_TOKEN_EXPIRES_DAYS is None)
                ):
                    raise Exception(
                        "TokensHandler :: refreshTokensIfNeeded :: Env vars not found"
                    )
                payload = jwt.decode(
                    refresh_token,
                    JWT_SECRET,
                    algorithms=[JWT_ALGORITHM],
                    options={"verify_exp": True},
                )
                if payload["token_type"] != "refresh":
                    return None, jsonify({"error": "Invalid refresh token"}), 401
                # Refresh token is valid; generate a new access token
                user_id = payload["user_id"]
                new_access_token = cls.createAccessToken(
                    data={"user_id": user_id},
                    expires_delta=timedelta(
                        minutes=float(ACCESS_TOKEN_EXPIRES_MINUTES)
                    ),
                )
                # Optionally, generate a new refresh token here as well

                # Set the new access token in the response
                resp = make_response()
                resp.set_cookie(
                    "access_token", new_access_token, httponly=True, samesite="Strict"
                )
                # Optionally, set the new refresh token in the response

                return {"user_id": user_id}, resp
            except jwt.PyJWTError:
                # Refresh token is invalid
                return None, jsonify({"error": "Invalid refresh token"}), 401

        # No valid access or refresh token
        return None, jsonify({"error": "Authentication required"}), 401

    @classmethod
    def refreshToken(cls, request):
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            return jsonify({"error": "Refresh token is missing"}), 401

        try:
            JWT_SECRET = os.getenv("JWT_SECRET")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
            ACCESS_TOKEN_EXPIRES_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES")
            if (
                (JWT_SECRET is None)
                or (JWT_ALGORITHM is None)
                or (ACCESS_TOKEN_EXPIRES_MINUTES is None)
            ):
                raise Exception(
                    "TokensHandler :: refreshTokensIfNeeded :: Env vars not found"
                )
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            token_type = payload.get("token_type")
            if not token_type or token_type != "refresh":
                return jsonify({"error": "Invalid refresh token"}), 401
            if not user_id:
                return jsonify({"error": "Invalid refresh token"}), 401

            # Generate a new access token
            access_token_expires = timedelta(
                minutes=float(ACCESS_TOKEN_EXPIRES_MINUTES)
            )
            new_access_token = cls.createAccessToken(
                data={"user_id": user_id}, expires_delta=access_token_expires
            )

            return jsonify({"access_token": new_access_token}), 200
        except jwt.PyJWTError:
            return jsonify({"error": "Invalid refresh token"}), 401
