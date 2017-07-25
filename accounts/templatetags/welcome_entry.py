from django import template
register = template.Library()

@register.simple_tag(takes_context=True)
def welcome_entry(context):
    # return "Fake Welcome Entry!"
    return ""

@register.simple_tag(takes_context=True)
def welcome_title(context):
    # return "Fake Welcome Title!"
    return ""
