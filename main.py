#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import hashlib
import json
import random
import string
import jinja2
import webapp2
import re
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))

config_filname = os.path.join(os.path.dirname(__file__), "config.json")
with open(config_filname) as config_file:
    config = json.load(config_file)

secret_key = config["secret"]


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def hash_str(self, s):
        return hashlib.sha256("{0}{1}".format(s, secret_key)).hexdigest()

    def make_salt(self):
        return "".join(random.choice(string.letters) for x in xrange(10))

    def make_pw_hash(self, email, pw, salt=None):
        if not salt:
            salt = self.make_salt()
        hash = self.hash_str("{0}{1}{2}".format(email, pw, salt))
        return "{0}|{1}".format(hash, salt)

    def valid_pw(self, name, pw, hash):
        salt = hash.split("|")[1]
        return hash == self.make_pw_hash(name, pw, salt)

    def set_cookie(self, name, val, path, secure):
        if secure:
            cookie_val = "{0}|{1}".format(self.hash_str(val), val)
        else:
            cookie_val = val
        self.response.headers.add_header(
            "Set-cookie",
            "{0}={1}; Path={2}".format(name, cookie_val, path)
        )

    def read_cookie(self, name, secure):
        cookie_val = self.request.cookies.get(name)
        if cookie_val and secure:
            return cookie_val.split("|")[1]
        else:
            return cookie_val

    def valid_cookie(self, name, cookie_val):
        val = cookie_val.split("|")[1]
        return cookie_val == "{0}|{1}".format(self.hash_str(val), val)


class Post(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created_time = db.DateTimeProperty(auto_now_add=True)


class User(db.Model):
    email = db.EmailProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)

    @classmethod
    def get_by_email(cls, email):
        return User.all().filter("email =", email).get()


class MainPage(Handler):
    def get(self):
        user = self.read_cookie("user", True)
        if user:
            self.render("index.html", user=user)
        else:
            self.render("landing.html")


class SignUpPage(Handler):
    def get(self):
        self.render("signup.html", error=None)

    def post(self, error=None):
        email = self.request.get("email")
        password = self.request.get("password")
        confirm = self.request.get("confirm-password")
        salt = self.make_salt()

        if len(email) == 0 or len(password) == 0 or len(confirm) == 0:
            error = "Missing one or more required fields."
        elif password != confirm:
            error = "Your passwords do not match."
        elif not (re.match(
                  r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                  email)):
            error = "You did not enter a valid email address."
        elif User.get_by_email(email):
            error = "A user with that email already exists."
        else:
            pw_hash = self.make_pw_hash(email, password, salt)
            user = User(email=db.Email(email), pw_hash=pw_hash, salt=salt)
            user_key = user.put()
            uid = user_key.id()
            self.set_cookie("user", str(uid), "/", True)
            self.redirect("/")
        self.render("signup.html", error=error)


class SignInPage(Handler):
    def get(self):
        self.render("signin.html")


class SignOut(Handler):
    def get(self):
        self.set_cookie("user", "", "/", False)
        self.redirect("/")

app = webapp2.WSGIApplication([
    ("/", MainPage),
    ("/signup", SignUpPage),
    ("/signin", SignInPage),
    ("/signout", SignOut)
], debug=True)
