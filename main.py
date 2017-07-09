#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2016 Google Inc.
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

import os
import webapp2
import jinja2
import logging
import random

from string import letters
import hashlib
import hmac

from google.appengine.ext import webapp
from google.appengine.ext import db
import google.appengine.api.mail as mail
from secret import secret
from admins import admins

# Image uploading
from google.appengine.api import memcache, images, app_identity
import json
import re
import urllib
import cloudstorage as gcs
import shutil
import tempfile
    
messages = \
    {'wb': "Welcome back!",
     'cbs': 'Come back soon!', 
     'wl': 'Welcome to the community!',
     'rd': 'Please use the buttons above to navigate!',
     'tc': 'I will be in touch soon!',
     'di': 'You did it!'}
actions = {'li': 'logged in',
           'lo': 'logged out',
           'su': 'registering',
           'dl': 'deleted an item',
           'em': 'sent an email',
           'blp': 'published a blog post',
           't': 'leaving a review'}

# ---------------------/
# --Global Functions--/
# -------------------/

def render_str(template, **params):
    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader('%s/templates/' % os.path.dirname(__file__))
    )
    t = jinja_env.get_template(template)
    return t.render(params)
    
class Handler(webapp2.RequestHandler):
    
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        user=self.get_user()
        if user:
            username = user.name
        else:
            username = ''

        self.write(self.render_str(
            template, 
            user=user, 
            currentTabs=self.get_currentTabs(), 
            navTab=self.get_navTab(), 
            username=username, 
            admin=self.admin_check(), 
            admins=admins, 
            **kw))
        
    def debug(self, text):
        logging.info(str(text))
    
    def admin_check(self, path=""):
        """
        Checks for admin and then 
            -returns True/False
            -renders path as html file if path exists
            
        depending on redir
        """
        
        try:
            usr = self.get_user().name.lower()
        except:
            usr = ''
            
        if str(usr) in admins:
            if path:
                self.render(path)
            else: 
                return True
        else:
            error = "Not signed in as admin, {}".format(usr)
            self.debug(error)
            if path:
                self.render('404.html', error=error)
            else:
                return False
    
    def get_gae_link(self, filename):
        bucket = os.environ.get('BUCKET_NAME',
                                app_identity.get_default_gcs_bucket_name())                
        link = "https://storage.googleapis.com/{bucket}/{filename}".format(
                    bucket=bucket,
                    filename=filename,
                )
        
        return link
    
    # -----
    # --Cookie Handling
    # -----

    def make_cookie(self, name, val):
        cookie = make_secure(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '{}={}; Path=/'.format(name, cookie)
        )

    def read_cookie(self, name):
        cookie = self.request.cookies.get(name)
        if cookie and check_secure(cookie):
            cookie_val = cookie.split('-')[0]
            return cookie_val

    # -----
    # --Authentication
    # -----

    def get_user(self):
        return User.by_id(self.read_cookie('user-id'))
    
    def get_navTab(self):
        s = str(self.request.path)
        return s
    
    def get_currentTabs(self):
        s = str(self.request.path)
        s = s.rsplit('/', 1)
        return s

    def login(self, user):
        self.make_cookie('user-id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user-id=; Path=/')

        
# -----
# --Security functions
# -----

def make_secure(val):
    return '{}-{}'.format(val, hmac.new(secret, val).hexdigest())


def check_secure(secure_val):
    val = secure_val.split('-')[0]
    if secure_val == make_secure(val):
        return val


# -----
# --Pw_hash
# -----

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '{}-{}'.format(salt, h)


def make_salt(length=5):
    for x in xrange(length):
        return ''.join(random.choice(letters))


# -----
# --pw_checking
# -----

def valid_pw(name, password, h):
    salt = h.split('-')[0]
    return h == make_pw_hash(name, password, salt)

#----------------------/
#--File uploading ----/
#--------------------/
#
# jQuery File Upload Plugin GAE Python Example
# https://github.com/blueimp/jQuery-File-Upload
#

DEBUG=os.environ.get('SERVER_SOFTWARE', '').startswith('Dev')
MIN_FILE_SIZE = 1  # bytes
# Max file size is memcache limit (1MB) minus key size minus overhead:
MAX_FILE_SIZE = 9990000 / 2  # 5 Mb
IMAGE_TYPES = re.compile('image/(gif|p?jpeg|(x-)?png)')
ACCEPT_FILE_TYPES = IMAGE_TYPES
THUMB_MAX_WIDTH = 80
THUMB_MAX_HEIGHT = 80
THUMB_SUFFIX = '.'+str(THUMB_MAX_WIDTH)+'x'+str(THUMB_MAX_HEIGHT)+'.png'
EXPIRATION_TIME = 300  # seconds
# If set to None, only allow redirects to the referer protocol+host.
# Set to a regexp for custom pattern matching against the redirect value:
REDIRECT_ALLOW_TARGET = None

class CORSHandler(webapp2.RequestHandler):
    def cors(self):
        headers = self.response.headers
        headers['Access-Control-Allow-Origin'] = '*'
        headers['Access-Control-Allow-Methods'] =\
            'OPTIONS, HEAD, GET, POST, DELETE'
        headers['Access-Control-Allow-Headers'] =\
            'Content-Type, Content-Range, Content-Disposition'

    def initialize(self, request, response):
        super(CORSHandler, self).initialize(request, response)
        self.cors()

    def json_stringify(self, obj):
        return json.dumps(obj, separators=(',', ':'))

    def options(self, *args, **kwargs):
        pass

class UploadHandler(CORSHandler, Handler):
    def validate(self, file):
        if file['size'] < MIN_FILE_SIZE:
            file['error'] = 'File is too small'
        elif file['size'] > MAX_FILE_SIZE:
            file['error'] = 'File is too big'
        elif not ACCEPT_FILE_TYPES.match(file['type']):
            file['error'] = 'Filetype not allowed'
        else:
            return True
        return False

    def validate_redirect(self, redirect):
        if redirect:
            if REDIRECT_ALLOW_TARGET:
                return REDIRECT_ALLOW_TARGET.match(redirect)
            referer = self.request.headers['referer']
            if referer:
                from urlparse import urlparse
                parts = urlparse(referer)
                redirect_allow_target = '^' + re.escape(
                    parts.scheme + '://' + parts.netloc + '/'
                )
            return re.match(redirect_allow_target, redirect)
        return False
    
    def get_file_size(self, file):
        file.seek(0, 2)  # Seek to the end of the file
        size = file.tell()  # Get the position of EOF
        file.seek(0)  # Reset the file position to the beginning
        return size

    def write_blob(self, data, info):
        key = urllib.quote(info['type'].encode('utf-8'), '') +\
            '/' + str(hash(data)) +\
            '/' + urllib.quote(info['name'].encode('utf-8'), '')
        try:
            memcache.set(key, data, time=EXPIRATION_TIME)
            self.debug("Added to memcache")
            self.debug(key.split("/")[0])
            try:
                bucket_name = os.environ.get('BUCKET_NAME',
                                   app_identity.get_default_gcs_bucket_name())
                self.debug(bucket_name)

                try:
                    filename = "/" + bucket_name + "/" + key.rsplit("/")[-1]
                except:
                    raise Exception("Something is wrong with the filename")

                self.debug(filename)

                write_retry_params = gcs.RetryParams(backoff_factor=1.1)

                self.debug("Retry params defined")
                self.debug("Starting to open gcs")
                
                cloudstorage_file = gcs.open(filename,
                         'w',
                         content_type=key.split("/")[0],
                         options={},
                         retry_params=write_retry_params)

                self.debug("Starting to open gcs")
                
                cloudstorage_file.write(data)
                cloudstorage_file.close()

                self.debug("Has been stored!")
            except Exception as e:
                self.debug("Error while storing")
                self.debug(e.args)
            
        except: #Failed to add to memcache
            return (None, None)
        thumbnail_key = None
        if IMAGE_TYPES.match(info['type']):
            try:
                img = images.Image(image_data=data)
                img.resize(
                    width=THUMB_MAX_WIDTH,
                    height=THUMB_MAX_HEIGHT
                )
                thumbnail_data = img.execute_transforms()
                thumbnail_key = key + THUMB_SUFFIX
                memcache.set(
                    thumbnail_key,
                    thumbnail_data,
                    time=EXPIRATION_TIME
                )
            except: #Failed to resize Image or add to memcache
                thumbnail_key = None                
        return (key, thumbnail_key)
    
                

    def handle_upload(self):
        results = []
        for name, fieldStorage in self.request.POST.items():
            if type(fieldStorage) is unicode:
                continue
            result = {}
            result['name'] = urllib.unquote(fieldStorage.filename)
            result['type'] = fieldStorage.type
            result['size'] = self.get_file_size(fieldStorage.file)
            if self.validate(result):
                key, thumbnail_key = self.write_blob(
                    fieldStorage.value,
                    result
                )
                if key is not None:
                    result['url'] = self.get_gae_link(result['name'])
                    result['user'] = User.by_id(int(self.read_cookie('user-id'))).name
                    if thumbnail_key is not None:
                        result['thumbnailUrl'] = self.request.host_url +\
                             '/' + thumbnail_key
                else:
                    self.debug('Failed to store uploaded fil to memcache')
            results.append(result)
        return results

    def head(self):
        pass

    def get(self):
        self.render("dashboard.html")

    def post(self):
        if self.admin_check():
            if (self.request.get('_method') == 'DELETE'):
                return self.delete()
            result = {'files': self.handle_upload()}
            s = self.json_stringify(result)
            redirect = self.request.get('redirect')
            if self.validate_redirect(redirect):
                return self.redirect(str(
                    redirect.replace('%s', urllib.quote(s, ''), 1)
                ))
            if 'application/json' in self.request.headers.get('Accept'):
                self.response.headers['Content-Type'] = 'application/json'
            self.response.write(s)
            self.debug("Success!!")

class FileHandler(CORSHandler):
    def normalize(self, str):
        return urllib.quote(urllib.unquote(str), '')

    def get(self, content_type, data_hash, file_name):
        content_type = self.normalize(content_type)
        file_name = self.normalize(file_name)
        key = content_type + '/' + data_hash + '/' + file_name
        data = memcache.get(key)
        if data is None:
            return self.error(404)
        # Prevent browsers from MIME-sniffing the content-type:
        self.response.headers['X-Content-Type-Options'] = 'nosniff'
        content_type = urllib.unquote(content_type)
        if not IMAGE_TYPES.match(content_type):
            # Force a download dialog for non-image types:
            content_type = 'application/octet-stream'
        elif file_name.endswith(THUMB_SUFFIX):
            content_type = 'image/png'
        self.response.headers['Content-Type'] = content_type
        # Cache for the expiration time:
        self.response.headers['Cache-Control'] = 'public,max-age=%d' \
            % EXPIRATION_TIME
        self.response.write(data)

    def delete(self, content_type, data_hash, file_name):
        content_type = self.normalize(content_type)
        file_name = self.normalize(file_name)
        key = content_type + '/' + data_hash + '/' + file_name
        result = {key: memcache.delete(key)}
        content_type = urllib.unquote(content_type)
        if IMAGE_TYPES.match(content_type):
            thumbnail_key = key + THUMB_SUFFIX
            result[thumbnail_key] = memcache.delete(thumbnail_key)
        if 'application/json' in self.request.headers.get('Accept'):
            self.response.headers['Content-Type'] = 'application/json'
        s = self.json_stringify(result)
        self.response.write(s)


# ---------------------/
# --DB----------------/
# -------------------/ 

class User(db.Model, Handler):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    exist_key = db.StringProperty()
    liked_posts = db.ListProperty(int)

    # Returns actual username from id

    @classmethod
    def name_by_id(cls, uid):
        if uid:
            return cls.get_by_id(int(uid)).name
        else:
            return None

    # Returns User

    @classmethod
    def by_id(cls, uid):
        if uid:
            return cls.get_by_id(int(uid))
        else:
            return None

    # Returns User

    @classmethod
    def by_name(cls, name):
        user = cls.all().filter('name =', name).get()
        return user

    # Returns Bool for existing name using exist_key

    @classmethod
    def exist(cls, name):
        exist = cls.all().filter('exist_key =', name.lower()).get()
        if exist:
            return True
        else:
            return False

    # Returns User class to register with

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name, pw_hash=pw_hash, exist_key=name.lower())

    # Returns user if password matches

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and valid_pw(name, pw, user.pw_hash):
            return user
        else:
            return None

    # Reads user-id and returns name

    @classmethod
    def current(cls):
        uid = cls.read_cookie('user-id')
        return User.name_by_id(uid)

class DBOBJECT(db.Model):
    mainImage = db.StringProperty()
    images = db.ListProperty(item_type=str)
    head = db.StringProperty(required=True)
    sub = db.StringProperty(required=True)
    main = db.TextProperty(required=True)
    cat = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    
    def _render_text(self):
        self.main.replace('\n', '<br>')
    
    def render(self):
        self._render_text()
        return self.render('portfolio.html', modal=self)
    
    @classmethod
    def render_txt(cls, text):
        return text.replace('\n', '<br>')
    
class ImgDB(db.Model):
    orImg = db.LinkProperty()
    thImg = db.LinkProperty()
    uploader = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    filesize = db.IntegerProperty()
    deleteUrl = db.StringProperty()
        
class ImgDBHandler(Handler):
    def post(self):
        if self.admin_check():
            data = self.request.POST.items()[0][0]
            data = json.loads(data)
            self.debug(data)

            try:
                error = data["error"]
            except:
                error = ""
            
            if error == "File is too big":
                self.debug("File too big!")
                self.render("dashboard.html", error=error)
            else:
                filename = data["name"]
                orImg = self.get_gae_link(filename)
                try:
                    thImg = data["thumbnailUrl"]
                except:
                    thImg = orImg # Temp full-size until implemented
                uploader = User.by_id(int(self.read_cookie('user-id'))).name
                filesize = data["size"]
                deleteUrl = orImg + "/delete"
                p = ImgDB(filename=filename, orImg=orImg, thImg=thImg, uploader=uploader, filesize=filesize, deleteUrl=deleteUrl)
                p.put()
                self.debug("Has been put!")
                
#                bucket_name = os.environ.get('BUCKET_NAME',
#                               app_identity.get_default_gcs_bucket_name())
#                self.debug(bucket_name)
#
#                filename = "/" + bucket_name + "/" + data["name"]
#
#                self.debug(filename)
#
#                write_retry_params = gcs.RetryParams(backoff_factor=1.1)
#
#                cloudstorage_file = gcs.open(filename,
#                         'w',
#                         content_type=data["type"],
#                         options=None,
#                         retry_params=write_retry_params)
#
#                with urllib.urlretrieve(data["url"], tempfile.TemporaryFile()) as temp:
#                    self.debug(temp.read())
#                
#                    cloudstorage_file.write(temp)
#                    cloudstorage_file.close()
#                    temp.close()
#                
#                self.debug("Has been stored!")
        else:
            self.redirect("/404")
                
    
    
class BlogDB(db.Model):
    mainImage = db.StringProperty()
    title = db.StringProperty()
    content = db.TextProperty()
    recipe = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.TextProperty()

    
    @classmethod
    def by_id(cls, bid):
        if bid:
            return cls.get_by_id(int(bid))
        else:
            return None

class BlogDBHandler(Handler):
    def get(self):
        self.render("dashboard.html")
    def post(self):
        if self.admin_check():
            mainImage = self.request.get("mainImage")
            title = self.request.get("Title")
            content = self.request.get("Content")
            recipe = self.request.get("Recipe")
            
            b = BlogDB(mainImage=mainImage,
                      title=title,
                      content=content,
                      recipe=recipe,
                      author=self.get_user().name.title()
                      )
            
            if mainImage and title and content and recipe and author:
                b.put()
                self.redirect("/success?action=blp&message=di")
            else: 
                
                error = "You missed one of the sections!" 
                self.render("dashboard.html", blog=b, error=error)
        else:
            self.redirect("/404")
            
# -----
# --Login pages
# -----
            
class SignUp(Handler):

    def get(self):
        if False:
            self.redirect('/404')
        else:
            self.render('register.html')

    def post(self):
        user = self.request.get('user')
        password = self.request.get('password')
        vPassword = self.request.get('vPassword')
        error = ''

        if user.lower() in admins and False:
            error = 'Username already exists. :('
            self.render('register.html', error=error)
        elif password == vPassword:
            self.debug("Passwords match")
            if user:
                if User.by_name(user) or User.exist(user):
                    error = 'Username already exists. :('
                    self.render('register.html', error=error)
                elif len(password) < 8:
                    error = \
                        'Password not secure enough; please make'\
                        'it AT LEAST 8 characters!'
                    self.render('register.html', error=error)
                else:
                    u = User.register(user, password)
                    u.put()
                    user = User.login(user, password)
                    self.login(u)
                    self.redirect('/thanks?action=su&message=wl')
            else:
                error = 'Please enter a username!'
                self.render('register.html', error=error)
        else:
            error = "Passwords don't match!"
            self.render('register.html', error=error)


class Login(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        user = self.request.get('user')
        password = self.request.get('password')
        error = ''

        user = User.login(user, password)
        if user:
            self.login(user)
            self.redirect('/success?action=li&message=wb')
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/success?action=lo&message=cbs')
            
# -----
# --Redirect pages
# -----

class Thanks(Handler):

    def get(self):
        action = self.request.get('action')
        message = self.request.get('message')

        self.render('thanks.html', action=actions[action],
                    message=messages[message])


class Success(Handler):

    def get(self):
        action = self.request.get('action')
        message = self.request.get('message')
        self.render('success.html', action=actions[action],
                    message=messages[message])


class NotFound(Handler):
    def get(self):
        self.render('404.html')
            
# ---------------------/
# --Pages-------------/
# -------------------/ 
    
class MainPage(Handler):
    def get(self):
        self.render("home.html")
        
class Store(Handler):
    def get(self):
        self.render("store.html")
    
class Blog(Handler):
    def get(self):
        self.render("blog.html")
        
class Dashboard(Handler):
    def get(self, bid=""):
        if self.admin_check():
            navTab = self.get_navTab()
            currentTabs = self.get_currentTabs()
            user = self.get_user().name

            if 'file' in currentTabs[-1]:
                files = db.GqlQuery("SELECT * FROM ImgDB where uploader = :1 order by created desc", user)
                self.render("dashboard.html", files=files)
            elif 'blog' in navTab and 'add' in navTab:
                self.render("dashboard.html")
            elif 'blog' in navTab and 'edit' in navTab:
                blog = BlogDB.by_id(bid)
                self.render("dashboard.html", blog=blog, bid=bid)
            elif 'blog' in navTab and 'delete' in navTab:
                blog = BlogDB.by_id(bid)
                blog.delete()
                self.redirect("/success?message=di&action=dl")
            elif 'blog' in currentTabs[-1]:
                blogs = db.GqlQuery("SELECT * FROM BlogDB order by created desc")
                self.render("dashboard.html", blogs=blogs)
            else:
                self.render("dashboard.html")
        else:
            self.redirect("/404")
    
    
class Contact(Handler):
    def get(self):
        self.render('contact.html')
        
    def post(self):
        name = self.request.get('name')
        subj = self.request.get('subj')
        body = self.request.get('body')
        return_address = self.request.get('email')
        sender_address = "Contact-form@website-157906.appspotmail.com"
        content = str("{}\n{}\n\n{}").format(name, return_address, body) 
        
        if name and subj and body and return_address:
            mail.send_mail(sender=sender_address,
                       to="Contact@KyleDiggs.com",
                       subject=subj,
                       body=content)
            self.redirect('/success?action=em&message=tc')
        else:
            error = "One or more sections weren't filled out!"
            self.render('contact.html', error=error, name=name, subj=subj, body=body, email=return_address)

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/login', Login),
    ('/logout', Logout),
    ('/contact', Contact),
    ('/blog', Blog),
    ('/dashboard', Dashboard), #Always admin checked
    ('/dashboard/file/add', UploadHandler),
    ('/dashboard/file/img/add', ImgDBHandler), #Admin Checked
    ('/dashboard/blog/add', BlogDBHandler), #Admin Checked
    ('/dashboard/blog/edit/([^/]+)', Dashboard), #Admin Checked
    ('/dashboard/blog/delete/([^/]+)', Dashboard), #Admin Checked
    ('/dashboard/.*', Dashboard), #Always admin checked
    ('/register', SignUp),
    ('/success', Success),
    ('/store', Store),
    ('/thanks', Thanks),
    ('/404', NotFound),
    ('/(.+)/([^/]+)/([^/]+)', FileHandler),
    ('/.*', NotFound)
    ], debug=True)
