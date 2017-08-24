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
import Image
    
messages = \
    {'wb': "Welcome back!",
     'cbs': 'Come back soon!', 
     'wl': 'Welcome to the community!',
     'rd': 'Please use the buttons above to navigate!',
     'tc': 'I will be in touch soon!',
     'di': 'You did it!'}
actions = {'li': 'logged in',
           'lo': 'logged out',
           'su': 'registered',
           'dl': 'deleted an item',
           'main': 'updated your main image',
           'em': 'sent an email',
           'blp': 'published a blog post',
           't': 'leaving a review'}

pages = {
    'contact': {
        'mainImage': '/images/macarooncrop.jpg'
    },
    'about': {
        'mainImage': '/images/macarooncrop.jpg'
    }
}

class social():
    twitter = ""
    instagram = ""
    facebook = ""
        
    @classmethod
    def getObj(self):
        if self.twitter == "" and self.instagram == "" and self.facebook == "":
            return None
        else:
            return self
    
social = social.getObj()


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

        if 'form' in kw:
            if self.read_cookie('showForm'):
                formHidden = True
            else:
                formHidden = kw['form']
        else:
            formHidden = True
            
        self.write(self.render_str(
            template, 
            user=user,
            mainImage=self.get_mainImage(),
            currentTabs=self.get_currentTabs(), 
            navTab=self.get_navTab(), 
            username=username, 
            admin=self.admin_check(), 
            admins=admins,
            pages=pages,
            formHidden=formHidden,
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
    
    def get_mainImage(self):
        q = db.GqlQuery("SELECT * FROM ImgDB where assigned = True order by created desc")
        # Get image - If there is an error stick to default
        try:
            image = q.get()
        except:
            self.debug("Can't get mainImage. Assigning default")
            return "https://storage.googleapis.com/misadventuresofbaking.appspot.com/macarooncrop.jpg"
        # If image exists (hasn't returned)
        try:
            link = image.orImg
            return link
        except Exception as e:
            self.debug(e)
            self.debug("No assigned values")
            return "https://storage.googleapis.com/misadventuresofbaking.appspot.com/macarooncrop.jpg"
    
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
        
        bucket_name = os.environ.get('BUCKET_NAME',
                           app_identity.get_default_gcs_bucket_name())

        filename = "/" + bucket_name + "/" + key.rsplit("/")[-1]
        
        f = data
        fl = images.resize(image_data=data, width=1500)
        fm = images.resize(image_data=data, width=750)
        fs = images.resize(image_data=data, width=300)
        fb = images.resize(image_data=data, width=150)
        
        filesizes = {
            "filename": filename,
            "original": {
                "size": "original",
                "data": f,
                "link": filename,
                "dimensions": {
                    "width": images.Image(image_data=f).width,
                    "height": images.Image(image_data=f).height
                }
            },
            "large": {
                "size": "large",
                "data": fl,
                "link": filename + "/large",
                "dimensions": {
                    "width": images.Image(fl).width,
                    "height": images.Image(fl).height
                }
            },
            "med": {
                "size": "med",
                "data": fm,
                "link": filename + "/med",
                "dimensions": {
                    "width": images.Image(fm).width,
                    "height": images.Image(fm).height
                }
            },
            "small": {
                "size": "small",
                "data": fs,
                "link": filename + "/small",
                "dimensions": {
                    "width": images.Image(fs).width,
                    "height": images.Image(fs).height
                }
            },
            "blur": {
                "size": "blur",
                "data": fb,
                "link": filename + "/blur",
                "dimensions": {
                    "width": images.Image(fb).width,
                    "height": images.Image(fb).height
                }
            }                
        }

        write_retry_params = gcs.RetryParams(backoff_factor=1.1)
        
        for item in filesizes:
            if filesizes[item] == "filename":
                pass
            else:
                try:
                    cloudstorage_file = gcs.open(filesizes[item]["link"],
                             'w',
                             content_type=key.split("/")[0],
                             options={'x-goog-acl': 'public-read'},
                             retry_params=write_retry_params)

                    cloudstorage_file.write(filesizes[item]["data"])
                    cloudstorage_file.close()
                    self.debug(filesizes[item]["size"] + "File has been successfully written!")
                except Exception as e:
                    self.debug("Failed")
        
        return True
                

    def handle_upload(self):
        results = []
        for name, fieldStorage in self.request.POST.items():
            if type(fieldStorage) is unicode:
                continue
            result = {}
            result['name'] = urllib.unquote(fieldStorage.filename)
            result['type'] = fieldStorage.type
            result['size'] = self.get_file_size(fieldStorage.file)
            result['url'] = self.get_gae_link(result['name'])
            result['user'] = User.by_id(int(self.read_cookie('user-id'))).name
            if self.validate(result):
                res = self.write_blob(
                    fieldStorage.value,
                    result
                )
                if res is False:
                    self.debug('Failed to store Image to GCS')
            else:
                self.debug(result)
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
    filename = db.StringProperty()
    deleteUrl = db.StringProperty()
    mainAssign = db.StringProperty()
    assigned = db.BooleanProperty()
    
    # Returns item

    @classmethod
    def by_id(cls, iid):
        if iid:
            return cls.get_by_id(int(iid))
        else:
            return None

        
class ImgDBHandler(Handler):
    def get(self):
        user = self.get_user().name
        navTab = self.get_navTab()
        currentTabs = self.get_currentTabs()
        
        if 'file' in currentTabs[-1]:
            files = db.GqlQuery("SELECT * FROM ImgDB where uploader = :1 order by created desc", user)
            self.render("dashboard.html", files=files)
            
    def post(self, *args):
        currentTabs = self.get_currentTabs()
        if "mainassign" in currentTabs[-1] and self.admin_check():
            self.clearMains()
            q = db.GqlQuery("SELECT * FROM ImgDB where filename = :1 order by created desc", args[1])
            obj = q.fetch(limit=1)
            image = obj[0]
            image.assigned = True
            image.put()
            
        elif "delete" in currentTabs[-1]:
            q = db.GqlQuery("SELECT * FROM ImgDB where filename = :1 order by created desc", args[1])
            obj = q.fetch(limit=1)
            image = obj[0]
            
            bucket_name = os.environ.get('BUCKET_NAME',
                               app_identity.get_default_gcs_bucket_name())

            try:
                gcs.delete("/" + bucket_name + "/" + image.filename)
                gcs.delete("/" + bucket_name + "/" + image.filename + "/large")
                gcs.delete("/" + bucket_name + "/" + image.filename + "/small")
                gcs.delete("/" + bucket_name + "/" + image.filename + "/med")
                gcs.delete("/" + bucket_name + "/" + image.filename + "/blur")
            except gcs.NotFoundError:
                pass
            except Exception as e:
                self.debug(e)
            
            image.delete()
            
        elif self.admin_check():
            data = self.request.POST.items()[0][0]
            data = json.loads(data)
            self.debug(data)

            try:
                error = data["error"]
            except:
                error = ""
            
            if error == "File is too big":
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
                deleteUrl = "/file/" + str(orImg.rsplit("/")[-2]) + "/" + str(orImg.rsplit("/")[-1])  + "/delete"
                mainAssign = "/dashboard/file/" + str(orImg.rsplit("/")[-2]) + "/" + str(orImg.rsplit("/")[-1])  + "/mainassign"
                p = ImgDB(filename=filename, orImg=orImg, thImg=thImg, uploader=uploader, filesize=filesize, deleteUrl=deleteUrl, mainAssign=mainAssign, assigned=False)
                p.put()
        else:
            self.redirect("/404")
        
    def clearMains(self):
        totalimages = db.GqlQuery("SELECT * FROM ImgDB where assigned = True")
        for item in totalimages:
            item.assigned = False
            item.put()
    
    
class BlogDB(db.Model):
    mainImage = db.StringProperty()
    title = db.StringProperty()
    summary = db.StringProperty()
    content = db.TextProperty()
    recipe = db.TextProperty()
    views = db.IntegerProperty(default=1)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.TextProperty()

    @classmethod
    def get_id(cls, blogObj):
        if blogObj:
            return blogObj.key().id()
        else:
            return None
    
    @classmethod
    def by_id(cls, bid):
        if bid:
            return cls.get_by_id(int(bid))
        else:
            return None
        
    @classmethod
    def get_link(cls, bid=""):
        if bid:
            return "/blog/" + str(bid)
        else:
            return None

class BlogDBHandler(Handler):
    def get(self, bid=""):
        user = self.get_user().name
        navTab = self.get_navTab()
        currentTabs = self.get_currentTabs()
        
        if 'blog' in navTab and 'add' in navTab:
            files = db.GqlQuery("SELECT * FROM ImgDB where uploader = :1 order by created desc", user)
            self.render("dashboard.html", files=files)
        elif 'blog' in navTab and 'edit' in navTab:
            files = db.GqlQuery("SELECT * FROM ImgDB where uploader = :1 order by created desc", user)
            blog = BlogDB.by_id(bid)
            self.render("dashboard.html", blog=blog, bid=bid, files=files)
        elif 'blog' in navTab and 'delete' in navTab:
            blog = BlogDB.by_id(bid)
            blog.delete()
            self.redirect("/success?message=di&action=dl")
        elif 'blog' in currentTabs[-1]:
            blogs = db.GqlQuery("SELECT * FROM BlogDB order by created desc")
            self.render("dashboard.html", blogs=blogs)
            
    def post(self, bid=""):
        if self.admin_check():           
            mainImage = self.request.get("mainImage")
            title = self.request.get("Title")
            content = self.request.get("Content")
            recipe = self.request.get("Recipe")
            summary = self.request.get("Summary")
            
            if bid != "":
                b = BlogDB.by_id(bid)
                b.mainImage = mainImage
                b.title = title
                b.content = content
                b.recipe = recipe
                b.summary = summary

                if mainImage and title and content and recipe:
                    b.put()
                    self.redirect("/dashboard/blog")
                else: 

                    error = "You missed one of the sections!" 
                    self.render("dashboard.html", blog=b, error=error)
                
            else:
                b = BlogDB(mainImage=mainImage,
                              title=title,
                              content=content,
                              recipe=recipe,
                              author=self.get_user().name.title()
                              )

                if mainImage and title and content and recipe:
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
                    self.redirect('/success?action=su&message=wl')
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
        q1 = db.GqlQuery("SELECT * from BlogDB order by created desc")
        q2 = db.GqlQuery("SELECT * from BlogDB order by views desc")
        try:
            mainBlog = q1.get()
            recentBlogs = q1.fetch(limit=8)
        except Exception as e:
            self.debug(e)
            
        try:
            featuredBlogs = q2.fetch(limit=2)
        except Exception as e:
            self.debug(e)
        self.render("index.html", form=False, featured=featuredBlogs, recents=recentBlogs, mainBlog=mainBlog)
        
class About(Handler):
    def get(self):
        self.render("about.html")
        
class Store(Handler):
    def get(self):
        self.render("store.html")
    
class Blog(Handler):
    def get(self, bid=""):
        if bid != "":
            blog = BlogDB.by_id(bid)
            blog.views += 1
            try:
                keywords = ", ".join(blog.summary.split())
            except:
                keywords = ""
            blogs = db.GqlQuery("SELECT * FROM BlogDB ORDER BY created DESC")
            blog.put()
            self.render("detail_blog.html", social=social, form=False, keywords=keywords, blog=blog, blogs=blogs)
        else:
            blogs = db.GqlQuery("SELECT * FROM BlogDB ORDER BY created DESC")
            self.render("blog.html", blogs=blogs)
        
class Dashboard(Handler):
    def get(self, bid=""):
        if self.admin_check():
            self.render("dashboard.html")
        else:
            self.redirect("/404")
    
    
class Contact(Handler):
    def get(self):
        self.render('contact.html', form=False)
        
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
    ('/about', About),
    ('/login', Login),
    ('/logout', Logout),
    ('/contact', Contact),
    ('/blog', Blog),
    ('/blog/([^/]+)', Blog),
    ('/dashboard', Dashboard), #Always admin checked
    ('/dashboard/file/add', UploadHandler),
    ('/dashboard/file', ImgDBHandler),
    ('/dashboard/file/img/add', ImgDBHandler), #Admin Checked
    ('/dashboard/file/([^/]+)/([^/]+)/mainassign', ImgDBHandler), #Admin Checked
    ('/file/([^/]+)/([^/]+)/delete', ImgDBHandler), #User checked
    ('/dashboard/blog', BlogDBHandler), #Admin Checked
    ('/dashboard/blog/add', BlogDBHandler), #Admin Checked
    ('/dashboard/blog/edit/([^/]+)', BlogDBHandler), #Admin Checked
    ('/dashboard/blog/delete/([^/]+)', BlogDBHandler), #Admin Checked
    ('/dashboard/.*', Dashboard), #Always admin checked
    ('/register', SignUp),
    ('/success', Success),
    ('/store', Store),
    ('/thanks', Thanks),
    ('/404', NotFound),
    ('/(.+)/([^/]+)/([^/]+)', FileHandler),
    ('/.*', NotFound)
    ], debug=True)