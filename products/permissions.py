"""
Custom permission classes for role-based access control.
"""
from rest_framework import permissions


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Permission class that allows read-only access to anyone,
    but write access only to admin users.
    """
    
    def has_permission(self, request, view):
        # Allow read-only methods for all users
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for admin users
        return request.user and request.user.is_staff


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission class that allows access to object owners or admin users.
    """
    
    def has_object_permission(self, request, view, obj):
        # Admin users have full access
        if request.user and request.user.is_staff:
            return True
        
        # Check if object has user attribute
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        return False


class IsCustomer(permissions.BasePermission):
    """
    Permission class for authenticated customer users.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsVerifiedCustomer(permissions.BasePermission):
    """
    Permission class for verified customer users.
    """
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            getattr(request.user, 'is_verified', False)
        )
