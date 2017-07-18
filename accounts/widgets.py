# Some BS-friendly widgets

from django.forms.widgets import TextInput, CheckboxInput
from django.utils.html import format_html


class BSLeftIconTextInput(TextInput):
    """A text input with a bootstrap icon on the left side of the field.
    """

    TEMPLATE = """<div class="left-inner-addon">
    <i class="{icon_class}"></i>
    {default_input}
</div>
    """

    def __init__(self, attrs=None, icon_class=''):
        attrs = attrs or {}
        attrs.update({'class': 'form-control'})
        self.icon_class = icon_class
        super(BSLeftIconTextInput, self).__init__(attrs)

    def render(self, name, value, attrs=None):
        default_input = super(BSLeftIconTextInput, self).render(name, value,
                                                                attrs)

        return self.TEMPLATE.format(default_input=default_input,
                                    icon_class=self.icon_class)

class BSLeftIconPasswordInput(BSLeftIconTextInput):
    input_type = 'password'

    def render(self, name, value, *args, **kwargs):
        """Clear password on render, so it's not sent back to the client.
        """
        # A weird hack to avoid a weird bug - sorry I didn't have time
        # to work this one out. RDH 07/17/2017
        kwargs.pop('renderer', None)
        return super(BSLeftIconPasswordInput, self).render(name, None, *args,
                                                           **kwargs)

class BSLeftIconEmailInput(BSLeftIconTextInput):
    input_type = 'email'
