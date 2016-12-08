import os
import re
import random
import string
import hmac

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-].{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


class User(db.Model):
    username = db.StringProperty(required=True)
    hashp = db.StringProperty(required=True)
    email = db.EmailProperty()


class Entry(db.Model):
    user = db.ReferencePropert(User, required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class PasswordUtil():
    def generate_salt_str(self):
        return "".join([random.choice(string.letters) for i in range(5)])

    def get_hash_password(self, p, salt=None):
        salt = salt if(salt) else self.generate_salt_str()
        return "%s|%s" % (salt, hmac.new(salt, p).hexdigest())


class FormValidator():
    def valid_username(self, username):
        return USERNAME_RE.match(username)

    def valid_password(self, password):
        return PASSWORD_RE.match(password)

    def valid_email(self, email):
        return EMAIL_RE.match(email)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **params):
        self.response.write(*a, **params)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        self.write(self.render_str(template, **params))


class SignupHandler(Handler):
    def get(self):
        user_id = self.request.cookies.get("user_id", None)
        if(user_id):
            self.redirect("/blog")
        else:
            self.render("signup.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = {}
        params["valid_username"] = FormValidator.valid_username(username)
        params["valid_password"] = FormValidator.valid_password(password)
        params["valid_verify"] = password == verify
        if(email):
            params["valid_email"] = FormValidator.valid_email(email)
        else:
            params["valid_email"] = True

        if(params["valid_username"] and params["valid_password"] and
           params["valid_verify"] and params["valid_email"]):
            pass
        else:
            params["username"] = username
            params["email"] = email
            self.render("signup.html", **params)
