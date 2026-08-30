from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, Length


class GroupForm(FlaskForm):
    name = StringField('Group name', validators=[DataRequired(), Length(min=2, max=120)])
    submit = SubmitField('Create Group')


class InviteMemberForm(FlaskForm):
    email = StringField('Member email', validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField(
        'Role',
        choices=[
            ('member', 'Member'),
            ('editor', 'Editor'),
        ],
        validators=[DataRequired()]
    )
    submit = SubmitField('Add Member')


class CompoundGroupForm(FlaskForm):
    group_id = SelectField('Group', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Add to Group')
