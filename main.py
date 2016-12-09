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
PASSWORD_RE = re.compile(r"^[a-zA-Z0-9].{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_username(username):
    return USERNAME_RE.match(username)


def valid_password(password):
    return PASSWORD_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email)


def generate_salt_str():
    return "".join([random.choice(string.letters) for i in range(5)])


def get_hash_password(p, salt=None):
    salt = salt if(salt) else generate_salt_str()
    return "%s|%s" % (salt, hmac.new(salt, p).hexdigest())


class User(db.Model):
    username = db.StringProperty(required=True)
    hashp = db.StringProperty(required=True)
    email = db.EmailProperty()


class Entry(db.Model):
    user = db.ReferenceProperty(User, required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    liked_by = db.ListProperty(db.Key)
    created = db.DateTimeProperty(auto_now_add=True)


class Comment(db.Model):
    user = db.ReferenceProperty(User, required=True)
    entry = db.ReferenceProperty(Entry, required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **params):
        self.response.write(*a, **params)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        params["current_user"] = self.current_user
        self.write(self.render_str(template, **params))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.current_user = None
        user_cookie = self.request.cookies.get("user_id", None)
        if(user_cookie):
            user_id = user_cookie.split("|")[0]
            if(user_id and User.get_by_id(int(user_id))):
                user = User.get_by_id(int(user_id))
                cookie_hash = user_cookie.split("|")[1]
                if(user.hashp.split("|")[1] == cookie_hash):
                    self.current_user = user


class MainPageHandler(Handler):
    def get(self):
        self.render("main.html")


class SignupHandler(Handler):
    def get(self):
        self.render("signup.html", signup_page=True)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = {}
        params["signup_page"] = True
        params["username"] = username
        params["email"] = email
        params["valid_username"] = valid_username(username)
        params["valid_password"] = valid_password(password)
        params["valid_verify"] = password == verify
        if(email):
            params["valid_email"] = valid_email(email)
        else:
            params["valid_email"] = True

        if(params["valid_username"] and params["valid_password"] and
           params["valid_verify"] and params["valid_email"]):
            exist_user = User.gql("WHERE username = :username",
                                  username=username).get()
            exist_email = User.gql("WHERE email = :email", email=email).get()
            if(exist_user or exist_email):
                params["username_taken"] = exist_user
                params["email_taken"] = exist_email
                self.render("signup.html", **params)
            else:
                user = User(username=username,
                            hashp=get_hash_password(password))
                if(email):
                    user.email = db.Email(email)
                user_key = user.put()
                user_cookie = "%s|%s" % (user_key.id(),
                                         user.hashp.split("|")[1])
                self.response.set_cookie("user_id", str(user_cookie),
                                         path="/")
                self.redirect("/blog")
        else:
            self.render("signup.html", **params)


class LoginHandler(Handler):
    def get(self):
        self.render("login.html", login_page=True)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        params = {}
        params["login_page"] = True
        params["valid_username"] = valid_username(username)
        params["valid_password"] = valid_password(password)
        params["username"] = username

        if(params["valid_username"] and params["valid_password"]):
            user = User.all().filter("username =", username).get()
            if(user):
                salt = str(user.hashp.split("|")[0])
                if(user.hashp == get_hash_password(password, salt)):
                    user_cookie = "%s|%s" % (user.key().id(),
                                             user.hashp.split("|")[1])
                    self.response.set_cookie("user_id", str(user_cookie),
                                             path="/")
                    self.redirect("/blog")

        params["invalid_login"] = True
        self.render("login.html", **params)


class LogoutHandler(Handler):
    def get(self):
        self.response.delete_cookie("user_id")
        self.redirect("/login")


class BlogHandler(Handler):
    def get(self):
        params = {}
        params["entries"] = Entry.all().order("-created")
        self.render("blog.html", **params)

    def post(self):
        params = {}
        if(self.current_user):
            entry_id = int(self.request.get("entry_id"))
            entry = Entry.get_by_id(entry_id)
            if(self.current_user.key() in entry.liked_by):
                entry.liked_by.remove(self.current_user.key())
            else:
                entry.liked_by.append(self.current_user.key())
            entry.put()
            params["entries"] = entry.all().order("-created")
            self.render("blog.html", **params)
        else:
            self.redirect("/login")


class NewPostHandler(Handler):
    def get(self):
        if(self.current_user):
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        params = {}
        params["subject"] = subject
        params["content"] = content

        if(subject and content):
            user_id = self.request.cookies.get("user_id", None)
            if(user_id):
                entry = Entry(user=User.get_by_id(int(user_id.split("|")[0])),
                              subject=subject, content=content)
                entry.put()
                self.redirect("/blog")
            else:
                self.redirect("/login")
        else:
            params["invalid"] = True
            self.render("newpost.html", **params)


class EntryHandler(Handler):
    def get(self, entry_id):
        if(self.current_user):
            params = {}
            entry = Entry.get_by_id(int(entry_id))

            entry_comments = Comment.all().filter("entry =", entry)
            entry_comments = entry_comments.order("-created")

            params["entry"] = entry
            params["entry_comments"] = entry_comments

            self.render("entry.html", **params)
        else:
            self.redirect("/login")

    def post(self, entry_id):
        entry = Entry.get_by_id(int(entry_id))

        params = {}
        entry_comments = Comment.all().filter("entry =", entry)

        if(self.request.get("like_entry")):
            if(self.current_user.key() in entry.liked_by):
                entry.liked_by.append(self.current_user.key())

            else:
                entry.liked_by.remove(self.current_user.key())

            entry.put()

        elif(self.request.get("edit")):
            params["edit_entry"] = True

        elif(self.request.get("edit_comment")):
            params["edit_comment"] = True
            params["comment_id"] = int(self.request.get("comment_id"))

        elif(self.request.get("add_comment")):
            content = self.request.get("new_comment_content")
            if(content):
                comment_model = Comment(user=self.current_user, entry=entry,
                                        content=content)
                comment_model.put()
                entry_comments = comment_model.all().filter("entry =", entry)

            else:
                params["new_comment_invalid"] = True

        else:
            if(self.request.get("save")):
                subject = self.request.get("subject")
                content = self.request.get("content")

                if(subject and content):
                    entry.subject = subject
                    entry.content = content
                    entry.put()

                else:
                    params["entry_invalid"] = True

            elif(self.request.get("delete")):
                entry.delete()
                self.redirect("/blog")

            elif(self.request.get("save_comment") or
                 self.request.get("delete_comment")):
                comment_id = int(self.request.get("comment_id"))
                comment = Comment.get_by_id(comment_id)

                if(self.request.get("save_comment")):
                    content = self.request.get("comment_content")

                    if(content):
                        comment.content = content
                        comment.put()

                    else:
                        params["comment_invalid"] = True

                else:
                    comment.delete()

                entry_comments = comment.all().filter("entry =", entry)

        params["entry"] = entry
        entry_comments = entry_comments.order("-created")
        params["entry_comments"] = entry_comments

        self.render("entry.html", **params)


app = webapp2.WSGIApplication([
    ("/", MainPageHandler),
    ("/signup", SignupHandler),
    ("/login", LoginHandler),
    ("/logout", LogoutHandler),
    ("/blog", BlogHandler),
    ("/blog/(\d+)", EntryHandler),
    ("/newpost", NewPostHandler)
])
