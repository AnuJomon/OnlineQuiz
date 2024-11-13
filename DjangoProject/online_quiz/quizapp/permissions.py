from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    """
    Custom permission to check if the user is an admin (i.e., `is_staff=True`).
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_staff  # Checks if the user is an admin
