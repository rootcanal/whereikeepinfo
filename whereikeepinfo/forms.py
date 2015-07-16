import formencode
import os

from pyramid_simpleform import Form


class FileValidator(formencode.FancyValidator):
    __unpackargs__ = ('upload_field', 'max_upload_size')

    def _to_python(self, field_storage, state):
        if field_storage is None:
            return field_storage
        fileobj = field_storage.file
        fileobj.seek(0, os.SEEK_END)
        size = int(fileobj.tell())
        if size > int(self.max_upload_size):
            raise formencode.Invalid(
                _('File too big'),
                field_storage, state,
                error_dict={self.upload_field:
                    formencode.Invalid(_('File too big'), field_storage, state)})
        fileobj.seek(0)
        return dict(filename=field_storage.filename, file=fileobj, size=size)


class RegistrationSchema(formencode.Schema):
    allow_extra_fields = True
    username = formencode.validators.PlainText(not_empty=True)
    password = formencode.validators.PlainText(not_empty=True)
    email = formencode.validators.Email(resolve_domain=False)
    name = formencode.validators.String(not_empty=True)
    password = formencode.validators.String(not_empty=True)
    confirm_password = formencode.validators.String(not_empty=True)
    chained_validators = [
        formencode.validators.FieldsMatch('password', 'confirm_password')
    ]

class LoginSchema(formencode.Schema):
    allow_extra_fields = True
    username = formencode.validators.PlainText(not_empty=True)
    password = formencode.validators.PlainText(not_empty=True)

class UploadFileSchema(formencode.Schema):
    allow_extra_fields = True
    uploaded_file = FileValidator(upload_field='uploaded_file', max_upload_size=10485760)
