from django.contrib.auth.models import Group

def populate_models(sender, **kwargs):
    supervisor_group, created = Group.objects.get_or_create(name='Supervisor')
    intern_group, created = Group.objects.get_or_create(name='Intern')
    
    return [supervisor_group,intern_group]