# Copyright 2015 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
For Hierarchical Role Based Access Control, roles are created that are allowed
access to a set of the Identity APIs like list_users, list_projects, list_roles.

These roles are psuedo-admin roles in the sense they are granted access to the
API via the policy.json but are allowed to see only a subset of the resources
a user with the 'admin' role will see.

The decorators in this module provide the filtering capability to show only
the resources a psuedo-admin role can see.
"""

import copy
import keystone
from keystone import exception
from keystone.i18n import _LE
from oslo_config import cfg
from oslo_log import log
from functools import wraps

CONF = cfg.CONF
LOG = log.getLogger(__name__)

def filter_projects(f):
    """
    Filter out the projects listed in the configuration file if the user is
    assigned a psuedo-admin role.

    This method filters out the names of the projects as defined in the
    keystone configuration file under the [api_filtering] section with the key
    'projects_to_filter' from the projects returned from the list_projects API.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):

        res = f(*args, **kwargs)
        is_admin_flag = _is_admin(args[0], args[1])

        if not is_admin_flag:
            if kwargs is not None and kwargs.get('project_id') is not None:
                if (res['project']['name']
                        in CONF.api_filtering.projects_to_filter):
                    msg = ("Project '%s' does not exist."
                           % kwargs.get('project_id'))
                    LOG.error(_LE(msg))
                    raise exception.NotFound(msg)
            else:
                refs = [project for project in res['projects']]
                for project in refs:
                    if (project['name']) in CONF.api_filtering.projects_to_filter:
                        res['projects'].remove(project)
        return res
    return wrapper

def filter_roles(f):
    """
    Filter out the roles listed in the configuration file if the user is
    assigned a psuedo-admin role.

    This method filters out the roles as defined in the keystone configuration
    file under the [api_filtering] section with the key 'roles_to_filter'
    from the roles returned from the list_roles API.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        res = f(*args, **kwargs)
        is_admin_flag = _is_admin(args[0], args[1])

        if not is_admin_flag:
            if kwargs is not None and kwargs.get('role_id') is not None:
                if res['role']['name'] in CONF.api_filtering.roles_to_filter:
                    msg = ("Role '%s' does not exist."
                           % kwargs.get('role_id'))
                    LOG.error(_LE(msg))
                    raise exception.NotFound(msg)
            else:
                refs = [role for role in res['roles']]
                for role in refs:
                    if (role['name']) in CONF.api_filtering.roles_to_filter:
                        res['roles'].remove(role)
        return res
    return wrapper


def filter_users(f):
    """
    Filter out the users from the user list retunred by invoking the list_users
    API
    For the Hierarchical Role Based Access Control the psuedo-admin roles do not
    have access to some of the tenants including the 'service' and the 'admin'
    projects. This filters out users from any of these filtered projects and
    returns the users only for the projects that are not filtered.
    It will also filter out any other users that are listed in the
    [api_filtering] section under the key 'explicit_users_to_filter'
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        project_details = {}
        res = f(*args, **kwargs)

        is_admin_flag = _is_admin(args[0], args[1])

        if not is_admin_flag:
            projects = _list_projects(args[0], args[1])

            for project in projects['projects']:
                if project['name'] in CONF.api_filtering.projects_to_filter:
                    project_details[project['name']] = project['id']

            if kwargs is not None and kwargs.get('user_id') is not None:
                if res['user'].get('default_project_id') is not None:
                    if (res['user']['default_project_id']
                            in project_details.values()):
                        msg = ("User '%s' does not exist."
                               % kwargs.get('user_id'))
                        LOG.error(_LE(msg))
                        raise exception.NotFound(msg)
            else:
                refs = [user for user in res['users']]

                for user in refs:
                    if (user.get('default_project_id') is not None and
                            user['default_project_id']
                            in project_details.values()):
                        res['users'].remove(user)

                    if (user.get('name')
                            in CONF.api_filtering.explicit_users_to_filter):
                        res['users'].remove(user)
        return res
    return wrapper

def _list_projects(self, context):
    projectV3 = keystone.resource.controllers.ProjectV3()
    refs = self.assignment_api.list_projects(hints=None)
    return projectV3.wrap_collection(context, refs, hints=None)

def _is_admin(self, context):
    """
    It indicates whether the performing actor is 'admin' or not.
    """
    if not context['is_admin']:
        for role_name in CONF.api_filtering.admin_role_name:
            if (role_name
                in context['environment']['KEYSTONE_AUTH_CONTEXT']['roles']):
                return True
            else:
                return False
    else:
        return True
