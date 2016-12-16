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
    """Return if username is valid"""
    return USERNAME_RE.match(username)


def valid_password(password):
    """Return if password is valid"""
    return PASSWORD_RE.match(password)


def valid_email(email):
    """Return if email is valid"""
    return EMAIL_RE.match(email)


def generate_salt_str(n=5):
    """Return random generated string with length n

    By default n = 5
    """
    return "".join([random.choice(string.letters) for i in range(n)])


def get_hash_password(p, salt=None):
    """Return a hashed password with salt

    Optional: salt is generated if not specified
    """
    salt = salt if(salt) else generate_salt_str()
    return "%s|%s" % (salt, hmac.new(salt, p).hexdigest())


def generate_user_cookie_str(u, h):
    """Return value for user_id cookie"""
    return str("%s|%s" % (u, h))


def user_parent_key(group="default"):
    """Return parent key for users"""
    return db.Key.from_path("users", group)


def entry_parent_key(group="default"):
    """Return parent key for blog entriers"""
    return db.Key.from_path("entrys", group)


def comment_parent_key(group="default"):
    """Return parent key for blog comments"""
    return db.Key.from_path("comments", group)


class User(db.Model):
    """User Model/Entity

    username    StringProperty
    hashp       StringProperty
    email       EmailProperty   Optional
    """
    username = db.StringProperty(required=True)
    hashp = db.StringProperty(required=True)
    email = db.EmailProperty()

    @classmethod
    def get_user_by_id(cls, id):
        """Return User with given id"""
        return User.get_by_id(id, parent=user_parent_key())

    @classmethod
    def get_user_by_username(cls, username):
        """Return User with given username"""
        return User.all().filter("username =", username).get()

    @classmethod
    def get_user_by_email(cls, email):
        """Return User with given email"""
        return User.all().filter("email =", email).get()

    @classmethod
    def create_user(cls, **params):
        """Return new User with attributes"""
        hashp = get_hash_password(params["password"])
        user = User(parent=user_parent_key(), username=params["username"],
                    hashp=hashp)
        if(params["email"]):
            user.email = db.Email(params["email"])
        return user


class Entry(db.Model):
    """Entry Model/Entity

    user        ReferenceProperty   User
    subject     StringProperty
    content     TextProperty
    liked_by    ListProperty        user.key()
    created     DateTimeProperty    auto
    """
    user = db.ReferenceProperty(User, required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    liked_by = db.ListProperty(db.Key)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_entries(cls):
        """Return all Entries"""
        return Entry.all().ancestor(entry_parent_key()).order("-created")

    @classmethod
    def get_entry_by_id(cls, id):
        """Return an Entry with the give id"""
        return Entry.get_by_id(id, parent=entry_parent_key())

    @classmethod
    def create_entry(cls, **params):
        """Return new Entry with attributes"""
        return Entry(parent=entry_parent_key(),
                     user=params["user"],
                     subject=params["subject"],
                     content=params["content"])


class Comment(db.Model):
    """Comment Model.Entity

    user        ReferenceProperty   User
    entry       ReferenceProperty   Entry
    content     TextProperty
    created     DateTimeProperty    auto
    """
    user = db.ReferenceProperty(User, required=True)
    entry = db.ReferenceProperty(Entry, required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_comments(cls):
        """Return all comments"""
        return Comment.all().ancestor(comment_parent_key()).order("-created")

    @classmethod
    def get_comment_by_id(cls, id):
        """Return Comment with given id"""
        return Comment.get_by_id(id, parent=comment_parent_key())

    @classmethod
    def get_comments_by_entry(cls, entry):
        """Return all comments of a given entry"""
        comments = cls.get_comments()
        return comments.filter("entry =", entry)

    @classmethod
    def create_comment(cls, **params):
        """Return a new Comment with attributes"""
        return Comment(parent=comment_parent_key(),
                       user=params["user"],
                       entry=params["entry"],
                       content=params["content"])


class Handler(webapp2.RequestHandler):
    def write(self, *a, **params):
        self.response.write(*a, **params)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        params["current_user"] = self.current_user
        self.write(self.render_str(template, **params))

    def set_cookie(self, key, val, **params):
        self.response.set_cookie(key, val, **params)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.current_user = None
        user_cookie = self.request.cookies.get("user_id", None)
        if(user_cookie):
            user_id = user_cookie.split("|")[0]
            user = User.get_user_by_id(int(user_id))
            if(user):
                cookie_hash = user_cookie.split("|")[1]
                if(user.hashp.split("|")[1] == cookie_hash):
                    self.current_user = user
            else:
                self.response.delete_cookie("user_id")


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
            exist_user = User.get_user_by_username(username)
            exist_email = User.get_user_by_email(email)
            if(exist_user or exist_email):
                params["username_taken"] = exist_user
                params["email_taken"] = exist_email
                self.render("signup.html", **params)
            else:
                user = User.create_user(username=username, password=password,
                                        email=email)
                user_h = user.hashp.split("|")[1]
                user_key = user.put()
                user_cookie = generate_user_cookie_str(user_key.id(), user_h)

                self.set_cookie("user_id", user_cookie, path="/")
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
            user = User.get_user_by_username(username)
            if(user):
                salt = str(user.hashp.split("|")[0])
                if(user.hashp == get_hash_password(password, salt)):
                    user_h = user.hashp.split("|")[1]
                    user_cookie = generate_user_cookie_str(user.key().id(),
                                                           user_h)
                    self.set_cookie("user_id", user_cookie, path="/")
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
        params["entries"] = Entry.get_entries()
        self.render("blog.html", **params)


class NewPostHandler(Handler):
    def get(self):
        if(self.current_user):
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if(self.current_user):
            subject = self.request.get("subject")
            content = self.request.get("content")

            params = {}
            params["subject"] = subject
            params["content"] = content

            if(subject and content):
                if(self.current_user):
                    new_post = dict(user=self.current_user,
                                    subject=subject, content=content)
                    entry = Entry.create_entry(**new_post)
                    entry.put()
                    self.redirect("/blog")
                else:
                    self.redirect("/login")
            else:
                params["invalid"] = True
                self.render("newpost.html", **params)
        else:
            self.redirect("/login")


class EntryHandler(Handler):
    def get(self, entry_id):
        if(self.current_user):
            params = {}
            entry = Entry.get_entry_by_id(int(entry_id))

            params["entry"] = entry
            if(entry):
                params["entry_comments"] = Comment.get_comments_by_entry(entry)
                self.render("entry.html", **params)
            else:
                self.redirect("/blog")
        else:
            self.redirect("/login")

    def post(self, entry_id):
        if(self.current_user):
            params = {}
            entry = Entry.get_entry_by_id(int(entry_id))

            params["entry"] = entry
            if(entry):
                params["entry_comments"] = Comment.get_comments_by_entry(entry)
                content = self.request.get("new_comment_content")
                if(content):
                    new_comment = dict(user=self.current_user, entry=entry,
                                       content=content)
                    comment_model = Comment.create_comment(**new_comment)
                    comment_model.put()
                    self.redirect("/blog/%s" % entry.key().id())

                else:
                    params["new_comment_invalid"] = True
                    self.render("entry.html", **params)

            else:
                self.redirect("/blog")
        else:
            self.redirect("/login")


class LikePostHandler(Handler):
    def post(self, entry_id):
        if(self.current_user):
            entry = Entry.get_entry_by_id(int(entry_id))
            if(entry):
                if(self.current_user.key() in entry.liked_by):
                    entry.liked_by.remove(self.current_user.key())
                else:
                    entry.liked_by.append(self.current_user.key())
                entry.put()
                self.redirect(self.request.headers["Referer"])
            else:
                self.redirect("/")
        else:
            self.redirect("/login")


class EditPostHandler(Handler):
    def get(self, entry_id):
        if(self.current_user):
            entry = Entry.get_entry_by_id(int(entry_id))
            if(entry):
                if(entry.user.key().id() == self.current_user.key().id()):
                    comments = Comment.get_comments_by_entry(entry)
                    return self.render("entry.html", entry=entry,
                                       entry_comments=comments,
                                       edit_entry=True)
                else:
                    self.redirect("/blog/%s" % entry.key().id())
            self.redirect("/blog")
        else:
            self.redirect("/login")

    def post(self, entry_id):
        if(self.current_user):
            entry = Entry.get_entry_by_id(int(entry_id))
            if(entry):
                if(entry.user.key().id() == self.current_user.key().id()):
                    params = {}
                    subject = self.request.get("subject")
                    content = self.request.get("content")

                    if(subject and content):
                        entry.subject = subject
                        entry.content = content
                        entry.put()
                        self.redirect("/blog/%s" % entry.key().id())
                    else:
                        comments = Comment.get_comments_by_entry(entry)
                        params["entry_comments"] = comments
                        params["subject"] = subject
                        params["content"] = content
                        params["invalid_entry"] = True
                        params["edit_entry"] = True
                        self.render("newpost.html", **params)
                else:
                    self.redirect("/blog/%s" % entry.key().id())
            else:
                self.redirect("/blog")
        else:
            self.redirect("/login")


class DeletePostHandler(Handler):
    def post(self, entry_id):
        if(self.current_user):
            entry = Entry.get_entry_by_id(int(entry_id))
            if(entry and
               (entry.user.key().id() == self.current_user.key().id())):
                entry.delete()

            self.redirect("/blog")
        else:
            self.redirect("/login")


class EditCommentHandler(Handler):
    def get(self, entry_id, comment_id):
        if(self.current_user):
            comment = Comment.get_comment_by_id(int(comment_id))
            entry = Entry.get_entry_by_id(int(entry_id))
            if(entry and comment):
                if(comment.user.key().id() == self.current_user.key().id()):
                    comments = Comment.get_comments_by_entry(entry)
                    params = {}
                    params["entry"] = entry
                    params["entry_comments"] = comments
                    params["edit_comment"] = True
                    params["comment_id"] = int(comment_id)
                    self.render("entry.html", **params)
            else:
                self.redirect("/blog")
        else:
            self.redirect("/login")

    def post(self, entry_id, comment_id):
        if(self.current_user):
            comment = Comment.get_comment_by_id(int(comment_id))
            entry = Entry.get_entry_by_id(int(entry_id))
            if(comment and entry):
                if(comment.user.key().id() == self.current_user.key().id()):
                    content = self.request.get("comment_content")
                    if(content):
                        comment.content = content
                        comment.put()
                        self.redirect("/blog/%s" % (entry_id))

                    else:
                        comments = Comment.get_comments_by_entry(entry)
                        params = {}
                        params["entry"] = entry
                        params["entry_comments"] = comments
                        params["edit_comment"] = True
                        params["comment_id"] = comment_id
                        params["comment_invalid"] = True
                        self.render("entry.html", **params)

            else:
                self.redirect("/blog")
        else:
            self.redirect("/login")


class DeleteCommentHandler(Handler):
    def post(self, entry_id, comment_id):
        if(self.current_user):
            entry = Entry.get_entry_by_id(int(entry_id))
            comment = Comment.get_comment_by_id(int(comment_id))
            if(entry and comment):
                if(comment.user.key().id() == self.current_user.key().id()):
                    comment.delete()
                    return self.redirect("/blog/%s" % entry_id)

            self.redirect("/blog")
        else:
            self.redirect("/login")

app = webapp2.WSGIApplication([
    ("/", MainPageHandler),
    ("/signup", SignupHandler),
    ("/login", LoginHandler),
    ("/logout", LogoutHandler),
    ("/newpost", NewPostHandler),
    ("/blog", BlogHandler),
    ("/blog/(\d+)", EntryHandler),
    ("/blog/(\d+)/like", LikePostHandler),
    ("/blog/(\d+)/edit", EditPostHandler),
    ("/blog/(\d+)/delete", DeletePostHandler),
    ("/blog/(\d+)/comments/(\d+)", EditCommentHandler),
    ("/blog/(\d+)/comments/(\d+)/delete", DeleteCommentHandler)
])
