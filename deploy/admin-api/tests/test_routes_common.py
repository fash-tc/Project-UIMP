import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest

from auth import User, BypassUser
from routes._common import has_permission


def test_user_with_perm_passes():
    u = User(username="alice", permissions=["manage_ai", "view_audit"])
    assert has_permission(u, "manage_ai")


def test_user_without_perm_fails():
    u = User(username="bob", permissions=["view_audit"])
    assert not has_permission(u, "manage_ai")


def test_bypass_user_has_all_perms():
    b = BypassUser(username="__bypass__:0", permissions=["*"])
    assert has_permission(b, "manage_ai")
    assert has_permission(b, "any.weird.perm")
