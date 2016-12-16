import random
import hmac

from google.appengine.ext import db


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
