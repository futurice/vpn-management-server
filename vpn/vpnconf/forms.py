""" Forms for creating VPN certificates """
from django import forms
from models import Employment, Computertype, Computerowner

class UploadFileForm(forms.Form):
    """ Form for either uploading CSR file or pasting it to textfield """
    file  = forms.FileField(label='Upload CSR file', required=False)
    certificatefield = forms.CharField ( widget=forms.widgets.Textarea(), label='Or paste contents to here', required=False )

class SMSForm(forms.Form):
    """ Form for inputting password after receiving it via SMS """
    passwordfield = forms.CharField ( widget=forms.widgets.PasswordInput(), label='Password' )

class PreferencesForm(forms.Form):
    """ CSR preferences form """
    employment = forms.ModelChoiceField(queryset=Employment.objects.all(), label='Employment status:')
    computer_owner = forms.ModelChoiceField(queryset=Computerowner.objects.all(), empty_label=None, label='Owner:')
    computer_type = forms.ModelChoiceField(queryset=Computertype.objects.all(), empty_label=None, label='Computer type:')
