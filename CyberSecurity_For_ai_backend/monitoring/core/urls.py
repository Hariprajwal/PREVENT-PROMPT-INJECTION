from django.urls import path
from .views import ChatbotLogView, SessionsView, AlertsView, UsersListView
from .analytics_views import UserSummaryView, UserAnalyticsView, UserLogsView

urlpatterns = [
    # Chatbot logging endpoint (called by api_server.py)
    path("chatbot/log/", ChatbotLogView.as_view()),

    # Security dashboard endpoints
    path("sessions/", SessionsView.as_view()),
    path("alerts/", AlertsView.as_view()),

    # User management
    path("users-list/", UsersListView.as_view()),

    # User analytics (per-user detail for Visual page)
    path("user/summary/", UserSummaryView.as_view()),
    path("user/analytics/", UserAnalyticsView.as_view()),
    path("user/logs/", UserLogsView.as_view()),
]
