from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, UserForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from os import getenv

# Initialize appilaction

app = Flask(__name__)
csrf_key = 'BLOG_SECRET'
secret = getenv(csrf_key)
db_key = 'DATABASE_URL'
db_url = getenv(db_key, "sqlite:///blog.db")
print(secret)
app.config['SECRET_KEY'] = secret
#app.config['SECRET_KEY'] = '8BYkEfBA6OdonzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Foreignkey

    author_id = db.Column(db.Integer, db.ForeignKey("blog_user.id"))

    # Relationships

    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")


class User(UserMixin, db.Model):
    __tablename__ = "blog_user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    # Relationships
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))

    # Foreignkey

    author_id = db.Column(db.Integer, db.ForeignKey("blog_user.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

    # Relationships

    comment_author = relationship("User", back_populates="comments")
    post = relationship("BlogPost", back_populates="comments")


db.create_all()

user = User.query.get(1)


# Create login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if user:
        return render_template("index.html", all_posts=posts, user=user)
    else:
        return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # Create user form object
    user_form = UserForm()

    if user_form.validate_on_submit():
        new_user = User()

        # TODO Verify user email before adding
        if not User.query.filter_by(email=user_form.email.data).first():
            # Fill User ORM with data from form
            new_user.name = user_form.name.data
            new_user.email = user_form.email.data
            new_user.password = generate_password_hash(user_form.password.data,
                                                       method='pbkdf2:sha256',
                                                       salt_length=8)

            # Add to database

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for('get_all_posts'))

        # Redirect
        if user:
            return redirect(url_for('get_all_posts'), user=user)
        else:
            return redirect(url_for('get_all_posts'))

    # Return Template
    if user:
        return render_template("register.html", form=user_form, user=user)
    else:
        return render_template("register.html", form=user_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    user_login_form = LoginForm()
    print(User.query.filter_by(email=user_login_form.email.data).first())
    if user_login_form.validate_on_submit() and User.query.filter_by(email=user_login_form.email.data).first():
        u_obj = User.query.filter_by(email=user_login_form.email.data).first()
        u_entered_pw = user_login_form.password.data
        db_user_password = u_obj.password
        print(u_entered_pw)
        print(db_user_password)
        if check_password_hash(db_user_password, u_entered_pw):
            login_user(u_obj)
            return redirect(url_for('get_all_posts'))
        else:
            flash(u'Invalid password or username provided', 'error')
    elif user_login_form.validate_on_submit() and not User.query.filter_by(email=user_login_form.email.data).first():
        flash(u'Invalid password or username provided', 'error')
    if user:

        return render_template("login.html", form=user_login_form, user=user)
    else:
        return render_template("login.html", form=user_login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if comment_form.validate_on_submit():
        print("made it")
        comment = Comment(text=comment_form.body.data,
                          post_id=post_id,
                          author_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
        return render_template("post.html", post=requested_post, comment_form=comment_form)
    print("made it not")
    return render_template("post.html", post=requested_post, comment_form=comment_form)


@app.route("/about")
def about():
    if user:
        return render_template("about.html", user=user)
    else:
        return render_template("about.html")


@app.route("/contact")
def contact():
    if user:
        return render_template("contact.html", user=user)
    else:
        return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    if user:
        return render_template("make-post.html", form=form, user=user)
    else:
        return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        if user:
            return redirect(url_for("show_post", post_id=post.id, user=user))
        else:
           return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='localhost', port=4711)
