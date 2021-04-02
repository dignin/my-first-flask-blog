from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField
import email_validator

# WTForm


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class UserForm(FlaskForm):
    name = StringField("Enter your name", validators=[DataRequired()])
    email = StringField("Enter your email", validators=[DataRequired(),
                                                        Email("The email in not in the correct format")])
    password = PasswordField("Enter your password", validators=[DataRequired()])
    submit = SubmitField("Create user")


class LoginForm(FlaskForm):
    email = StringField("Enter your email", validators=[DataRequired(),
                                                        Email("The email in not in the correct format")])
    password = PasswordField("Enter your password", validators=[DataRequired()])
    submit = SubmitField("Log in")


class CommentForm(FlaskForm):
    body = CKEditorField("Comments", validators=[DataRequired()])
    submit = SubmitField("Add comment")
