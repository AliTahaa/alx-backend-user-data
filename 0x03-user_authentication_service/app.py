#!/usr/bin/env python3
""" app """
from auth import Auth
from flask import Flask, abort, jsonify, request, redirect, url_for

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True
AUTH = Auth()


@app.route("/")
def home() -> str:
  """ Home endpoint
    Returns:
      - Welcome message
  """
  return jsonify({"message": "Bienvenue"})


@app.route("/sessions", methods=["POST"])
def login():
  """ Login endpoint
    Form fields:
      - email
      - password
    Returns:
      - user email and login message
      - 401 if credentials are invalid
  """
  email = request.form.get("email")
  passw = request.form.get("password")
  if not AUTH.valid_login(email, passw):
    abort(401)
  s_id = AUTH.create_session(email)
  resp = jsonify({"email": email, "message": "logged in"})
  resp.set_cookie("session_id", s_id)
  return resp


@app.route("/sessions", methods=["DELETE"])
def logout():
  """ Logout endpoint
    Returns:
      - redirect to home
  """
  s_id = request.cookies.get("session_id")
  u = AUTH.get_user_from_session_id(s_id)
  if not u:
    abort(403)
  AUTH.destroy_session(u.id)
  return redirect(url_for("home"))


@app.route("/users", methods=["POST"])
def users():
  """ New user signup endpoint
    Form fields:
      - email
      - password
    Returns:
      - user email and creation message
      - 400 if email is already registered
  """
  email = request.form.get("email")
  passw = request.form.get("password")
  try:
    AUTH.register_user(email, passw)
    return jsonify({"email": email, "message": "user created"})
  except ValueError:
    return jsonify({"message": "email already registered"}), 400


@app.route("/profile")
def profile() -> str:
  """ User profile endpoint
    Returns:
      - user email
      - 403 if session_id is not linked to a user
  """
  s_id = request.cookies.get("session_id")
  u = AUTH.get_user_from_session_id(s_id)
  if not u:
    abort(403)
  return jsonify({"email": u.email})


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token() -> str:
  """ Reset password token endpoint
    Form fields:
      - email
    Returns:
      - email and reset token
      - 403 if email is not associated with a user
  """
  email = request.form.get("email")
  try:
    r_token = AUTH.get_reset_password_token(email)
  except ValueError:
    abort(403)

  return jsonify({"email": email, "reset_token": r_token})


@app.route("/reset_password", methods=["PUT"])
def update_password():
  """ Password update endpoint
    Form fields:
      - email
      - reset_token
      - new_password
    Returns:
      - user email and password update message
      - 403 if reset token is invalid
  """
  email = request.form.get("email")
  new_passw = request.form.get("new_password")
  r_token = request.form.get("reset_token")

  try:
    AUTH.update_password(r_token, new_passw)
  except ValueError:
    abort(403)
  return jsonify({"email": email, "message": "Password updated"})


if __name__ == "__main__":
  app.run(host="0.0.0.0", port="5000")
