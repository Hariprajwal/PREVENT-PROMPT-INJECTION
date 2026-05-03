from core.models import UserProfile


def get_or_create_profile(user_id):
    profile, _ = UserProfile.objects.get_or_create(user_id=user_id)
    return profile
