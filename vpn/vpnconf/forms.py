""" Forms for creating VPN certificates """
from django import forms
from models import Employment, Computertype, Computerowner
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit

class UploadFileForm(forms.Form):
    """ Form for either uploading CSR file or pasting it to textfield """
    file  = forms.FileField(label='Upload CSR file', required=False)
    certificatefield = forms.CharField ( widget=forms.widgets.Textarea(), label='Or paste contents to here', required=False )

class SMSForm(forms.Form):
    """ Form for inputting password after receiving it via SMS """
    passwordfield = forms.CharField ( widget=forms.widgets.PasswordInput(), label='Password' )
    def __init__(self, *args, **kwargs):
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'

        self.helper.add_input(Submit('submit', 'Continue'))
        super(SMSForm, self).__init__(*args, **kwargs)


class PreferencesForm(forms.Form):
    """ CSR preferences form """
    employment = forms.ModelChoiceField(queryset=Employment.objects.all(), label='Employment status:')
    computer_owner = forms.ModelChoiceField(queryset=Computerowner.objects.all(), empty_label=None, label='Owner:')
    computer_type = forms.ModelChoiceField(queryset=Computertype.objects.all(), empty_label=None, label='Computer type:')

    def __init__(self, *args, **kwargs):
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'

        self.helper.add_input(Submit('submit', 'Continue'))
        super(PreferencesForm, self).__init__(*args, **kwargs)
