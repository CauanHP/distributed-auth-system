"""
Streamlit Dashboard for Distributed Authentication System
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
import json
import requests
import io
from datetime import datetime, timedelta
from typing import Dict, Any, List
import base64


def main():
    st.set_page_config(
        page_title="Distributed Authentication Dashboard",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🔐 Distributed Authentication Dashboard")
    st.markdown("---")
    
    # Sidebar
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["System Overview", "User Management", "Role Management", "Permission Management", "Session Management", "Audit Logs", "Security Analytics"]
    )
    
    # API base URL
    api_base_url = st.sidebar.text_input("API Base URL", "http://localhost:8000")
    
    if page == "System Overview":
        system_overview_page(api_base_url)
    elif page == "User Management":
        user_management_page(api_base_url)
    elif page == "Role Management":
        role_management_page(api_base_url)
    elif page == "Permission Management":
        permission_management_page(api_base_url)
    elif page == "Session Management":
        session_management_page(api_base_url)
    elif page == "Audit Logs":
        audit_logs_page(api_base_url)
    elif page == "Security Analytics":
        security_analytics_page(api_base_url)


def system_overview_page(api_base_url: str):
    st.header("🖥️ System Overview")
    
    # Health check
    try:
        health_response = requests.get(f"{api_base_url}/health", timeout=5)
        if health_response.status_code == 200:
            health_data = health_response.json()
            st.success("✅ System is healthy")
            
            # Display service status
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Redis", "🟢 Connected" if health_data["services"]["redis"] == "connected" else "🔴 Disconnected")
            with col2:
                st.metric("Auth Service", "🟢 Ready" if health_data["services"]["auth_service"] == "ready" else "🔴 Not Ready")
            with col3:
                st.metric("RBAC Service", "🟢 Ready" if health_data["services"]["rbac_service"] == "ready" else "🔴 Not Ready")
            with col4:
                st.metric("MFA Service", "🟢 Ready" if health_data["services"]["mfa_service"] == "ready" else "🔴 Not Ready")
        else:
            st.error("❌ System health check failed")
    except Exception as e:
        st.error(f"❌ Cannot connect to authentication system: {e}")
        return
    
    # System metrics
    try:
        metrics_response = requests.get(f"{api_base_url}/metrics", timeout=5)
        if metrics_response.status_code == 200:
            metrics_data = metrics_response.json()
            display_system_metrics(metrics_data)
        else:
            st.warning("⚠️ Could not fetch system metrics")
    except Exception as e:
        st.warning(f"⚠️ Error fetching metrics: {e}")


def display_system_metrics(metrics: Dict[str, Any]):
    """Display system metrics"""
    st.subheader("📊 System Metrics")
    
    # Active sessions
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        active_sessions = metrics.get("active_sessions", 0)
        st.metric("Active Sessions", active_sessions)
    
    with col2:
        auth_stats = metrics.get("auth_stats", {})
        failed_attempts = auth_stats.get("failed_attempts", 0)
        st.metric("Failed Login Attempts", failed_attempts)
    
    with col3:
        locked_accounts = auth_stats.get("locked_accounts", 0)
        st.metric("Locked Accounts", locked_accounts)
    
    with col4:
        audit_stats = metrics.get("audit_stats", {})
        total_events = audit_stats.get("total_events", 0)
        st.metric("Total Audit Events", total_events)
    
    # Rate limiting stats
    st.subheader("🚦 Rate Limiting Statistics")
    rate_limit_stats = metrics.get("rate_limit_stats", {})
    
    if rate_limit_stats:
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Rate Limit Stats**")
            st.json(rate_limit_stats)
        
        with col2:
            # Create a simple chart for rate limiting
            if "requests_per_minute" in rate_limit_stats:
                fig = go.Figure()
                fig.add_trace(go.Indicator(
                    mode = "gauge+number",
                    value = rate_limit_stats["requests_per_minute"],
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Requests per Minute"},
                    gauge = {
                        'axis': {'range': [None, 1000]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 500], 'color': "lightgray"},
                            {'range': [500, 800], 'color': "yellow"},
                            {'range': [800, 1000], 'color': "red"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 800
                        }
                    }
                ))
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)


def user_management_page(api_base_url: str):
    st.header("👥 User Management")
    
    # User management tabs
    tab1, tab2, tab3, tab4 = st.tabs(["User List", "Create User", "User Details", "User Roles"])
    
    with tab1:
        st.subheader("📋 User List")
        
        if st.button("Refresh Users"):
            try:
                # This would call the actual API endpoint
                st.info("Fetching users...")
                # users_response = requests.get(f"{api_base_url}/users", timeout=5)
                # users_data = users_response.json()
                
                # For demo purposes, create sample data
                users_data = {
                    "users": [
                        {
                            "id": "1",
                            "username": "admin",
                            "email": "admin@example.com",
                            "full_name": "Administrator",
                            "is_active": True,
                            "mfa_enabled": True,
                            "last_login": "2024-01-01T10:00:00Z",
                            "created_at": "2024-01-01T00:00:00Z"
                        },
                        {
                            "id": "2",
                            "username": "user1",
                            "email": "user1@example.com",
                            "full_name": "Regular User",
                            "is_active": True,
                            "mfa_enabled": False,
                            "last_login": "2024-01-01T09:30:00Z",
                            "created_at": "2024-01-01T00:00:00Z"
                        }
                    ]
                }
                
                if users_data["users"]:
                    users_df = pd.DataFrame(users_data["users"])
                    st.dataframe(users_df, use_container_width=True)
                else:
                    st.info("No users found")
                
            except Exception as e:
                st.error(f"Error fetching users: {e}")
    
    with tab2:
        st.subheader("➕ Create New User")
        
        with st.form("create_user_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                username = st.text_input("Username")
                email = st.text_input("Email")
            
            with col2:
                full_name = st.text_input("Full Name")
                password = st.text_input("Password", type="password")
            
            mfa_enabled = st.checkbox("Enable MFA")
            
            submitted = st.form_submit_button("Create User")
            
            if submitted:
                if username and email and password:
                    try:
                        user_data = {
                            "username": username,
                            "email": email,
                            "full_name": full_name,
                            "password": password,
                            "mfa_enabled": mfa_enabled
                        }
                        
                        # This would call the actual API endpoint
                        # response = requests.post(f"{api_base_url}/users", json=user_data)
                        
                        st.success("✅ User created successfully!")
                        st.json(user_data)
                    except Exception as e:
                        st.error(f"Error creating user: {e}")
                else:
                    st.warning("Please fill in all required fields")
    
    with tab3:
        st.subheader("👤 User Details")
        
        user_id = st.text_input("Enter User ID")
        
        if user_id and st.button("Get User Details"):
            try:
                # This would call the actual API endpoint
                # response = requests.get(f"{api_base_url}/users/{user_id}")
                
                # Sample user details
                user_details = {
                    "id": user_id,
                    "username": "sample_user",
                    "email": "sample@example.com",
                    "full_name": "Sample User",
                    "is_active": True,
                    "mfa_enabled": True,
                    "last_login": "2024-01-01T10:00:00Z",
                    "created_at": "2024-01-01T00:00:00Z",
                    "login_attempts": 0,
                    "account_locked": False
                }
                
                st.json(user_details)
                
                # User actions
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("Deactivate User"):
                        st.warning("User deactivated")
                
                with col2:
                    if st.button("Reset Password"):
                        st.info("Password reset email sent")
                
                with col3:
                    if st.button("Unlock Account"):
                        st.success("Account unlocked")
                
            except Exception as e:
                st.error(f"Error fetching user details: {e}")
    
    with tab4:
        st.subheader("🎭 User Roles")
        
        user_id = st.text_input("Enter User ID for Role Management")
        
        if user_id and st.button("Get User Roles"):
            try:
                # This would call the actual API endpoint
                # response = requests.get(f"{api_base_url}/users/{user_id}/roles")
                
                # Sample user roles
                user_roles = {
                    "user_id": user_id,
                    "roles": [
                        {
                            "id": "1",
                            "name": "admin",
                            "description": "Administrator role",
                            "assigned_at": "2024-01-01T00:00:00Z"
                        },
                        {
                            "id": "2",
                            "name": "user",
                            "description": "Regular user role",
                            "assigned_at": "2024-01-01T00:00:00Z"
                        }
                    ]
                }
                
                st.json(user_roles)
                
                # Role management
                st.subheader("Assign/Remove Roles")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    role_to_assign = st.selectbox("Select Role to Assign", ["admin", "user", "moderator"])
                    if st.button("Assign Role"):
                        st.success(f"Role '{role_to_assign}' assigned to user")
                
                with col2:
                    role_to_remove = st.selectbox("Select Role to Remove", ["admin", "user", "moderator"])
                    if st.button("Remove Role"):
                        st.warning(f"Role '{role_to_remove}' removed from user")
                
            except Exception as e:
                st.error(f"Error fetching user roles: {e}")


def role_management_page(api_base_url: str):
    st.header("🎭 Role Management")
    
    # Role management tabs
    tab1, tab2, tab3 = st.tabs(["Role List", "Create Role", "Role Permissions"])
    
    with tab1:
        st.subheader("📋 Role List")
        
        if st.button("Refresh Roles"):
            try:
                # This would call the actual API endpoint
                # response = requests.get(f"{api_base_url}/roles")
                
                # Sample roles data
                roles_data = {
                    "roles": [
                        {
                            "id": "1",
                            "name": "admin",
                            "description": "Administrator role with full access",
                            "is_active": True,
                            "created_at": "2024-01-01T00:00:00Z",
                            "user_count": 5
                        },
                        {
                            "id": "2",
                            "name": "user",
                            "description": "Regular user role with limited access",
                            "is_active": True,
                            "created_at": "2024-01-01T00:00:00Z",
                            "user_count": 100
                        },
                        {
                            "id": "3",
                            "name": "moderator",
                            "description": "Moderator role with content management access",
                            "is_active": True,
                            "created_at": "2024-01-01T00:00:00Z",
                            "user_count": 10
                        }
                    ]
                }
                
                if roles_data["roles"]:
                    roles_df = pd.DataFrame(roles_data["roles"])
                    st.dataframe(roles_df, use_container_width=True)
                    
                    # Role statistics
                    st.subheader("📊 Role Statistics")
                    
                    fig = px.pie(
                        roles_df,
                        values='user_count',
                        names='name',
                        title="User Distribution by Role"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No roles found")
                
            except Exception as e:
                st.error(f"Error fetching roles: {e}")
    
    with tab2:
        st.subheader("➕ Create New Role")
        
        with st.form("create_role_form"):
            role_name = st.text_input("Role Name")
            role_description = st.text_area("Role Description")
            
            submitted = st.form_submit_button("Create Role")
            
            if submitted:
                if role_name:
                    try:
                        role_data = {
                            "name": role_name,
                            "description": role_description
                        }
                        
                        # This would call the actual API endpoint
                        # response = requests.post(f"{api_base_url}/roles", json=role_data)
                        
                        st.success("✅ Role created successfully!")
                        st.json(role_data)
                    except Exception as e:
                        st.error(f"Error creating role: {e}")
                else:
                    st.warning("Please enter a role name")
    
    with tab3:
        st.subheader("🔐 Role Permissions")
        
        role_id = st.selectbox("Select Role", ["1", "2", "3"])
        
        if role_id and st.button("Get Role Permissions"):
            try:
                # This would call the actual API endpoint
                # response = requests.get(f"{api_base_url}/roles/{role_id}/permissions")
                
                # Sample role permissions
                role_permissions = {
                    "role_id": role_id,
                    "role_name": "admin",
                    "permissions": [
                        {
                            "id": "1",
                            "name": "read_users",
                            "resource": "users",
                            "action": "read",
                            "description": "Read user information"
                        },
                        {
                            "id": "2",
                            "name": "write_users",
                            "resource": "users",
                            "action": "write",
                            "description": "Create and update users"
                        },
                        {
                            "id": "3",
                            "name": "delete_users",
                            "resource": "users",
                            "action": "delete",
                            "description": "Delete users"
                        }
                    ]
                }
                
                st.json(role_permissions)
                
                # Permission management
                st.subheader("Manage Permissions")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Available Permissions**")
                    available_permissions = [
                        {"id": "4", "name": "read_roles", "resource": "roles", "action": "read"},
                        {"id": "5", "name": "write_roles", "resource": "roles", "action": "write"},
                        {"id": "6", "name": "read_audit", "resource": "audit", "action": "read"}
                    ]
                    
                    for perm in available_permissions:
                        if st.button(f"Add {perm['name']}", key=f"add_{perm['id']}"):
                            st.success(f"Permission '{perm['name']}' added to role")
                
                with col2:
                    st.write("**Current Permissions**")
                    for perm in role_permissions["permissions"]:
                        if st.button(f"Remove {perm['name']}", key=f"remove_{perm['id']}"):
                            st.warning(f"Permission '{perm['name']}' removed from role")
                
            except Exception as e:
                st.error(f"Error fetching role permissions: {e}")


def permission_management_page(api_base_url: str):
    st.header("🔐 Permission Management")
    
    # Permission management tabs
    tab1, tab2 = st.tabs(["Permission List", "Create Permission"])
    
    with tab1:
        st.subheader("📋 Permission List")
        
        if st.button("Refresh Permissions"):
            try:
                # This would call the actual API endpoint
                # response = requests.get(f"{api_base_url}/permissions")
                
                # Sample permissions data
                permissions_data = {
                    "permissions": [
                        {
                            "id": "1",
                            "name": "read_users",
                            "resource": "users",
                            "action": "read",
                            "description": "Read user information",
                            "is_active": True,
                            "created_at": "2024-01-01T00:00:00Z"
                        },
                        {
                            "id": "2",
                            "name": "write_users",
                            "resource": "users",
                            "action": "write",
                            "description": "Create and update users",
                            "is_active": True,
                            "created_at": "2024-01-01T00:00:00Z"
                        },
                        {
                            "id": "3",
                            "name": "delete_users",
                            "resource": "users",
                            "action": "delete",
                            "description": "Delete users",
                            "is_active": True,
                            "created_at": "2024-01-01T00:00:00Z"
                        },
                        {
                            "id": "4",
                            "name": "read_roles",
                            "resource": "roles",
                            "action": "read",
                            "description": "Read role information",
                            "is_active": True,
                            "created_at": "2024-01-01T00:00:00Z"
                        },
                        {
                            "id": "5",
                            "name": "write_roles",
                            "resource": "roles",
                            "action": "write",
                            "description": "Create and update roles",
                            "is_active": True,
                            "created_at": "2024-01-01T00:00:00Z"
                        }
                    ]
                }
                
                if permissions_data["permissions"]:
                    permissions_df = pd.DataFrame(permissions_data["permissions"])
                    st.dataframe(permissions_df, use_container_width=True)
                    
                    # Permission statistics
                    st.subheader("📊 Permission Statistics")
                    
                    # Group by resource
                    resource_counts = permissions_df.groupby('resource').size().reset_index(name='count')
                    
                    fig = px.bar(
                        resource_counts,
                        x='resource',
                        y='count',
                        title="Permissions by Resource"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Group by action
                    action_counts = permissions_df.groupby('action').size().reset_index(name='count')
                    
                    fig = px.pie(
                        action_counts,
                        values='count',
                        names='action',
                        title="Permissions by Action"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No permissions found")
                
            except Exception as e:
                st.error(f"Error fetching permissions: {e}")
    
    with tab2:
        st.subheader("➕ Create New Permission")
        
        with st.form("create_permission_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                permission_name = st.text_input("Permission Name")
                resource = st.text_input("Resource")
            
            with col2:
                action = st.selectbox("Action", ["read", "write", "delete", "execute", "manage"])
                description = st.text_area("Description")
            
            submitted = st.form_submit_button("Create Permission")
            
            if submitted:
                if permission_name and resource and action:
                    try:
                        permission_data = {
                            "name": permission_name,
                            "resource": resource,
                            "action": action,
                            "description": description
                        }
                        
                        # This would call the actual API endpoint
                        # response = requests.post(f"{api_base_url}/permissions", json=permission_data)
                        
                        st.success("✅ Permission created successfully!")
                        st.json(permission_data)
                    except Exception as e:
                        st.error(f"Error creating permission: {e}")
                else:
                    st.warning("Please fill in all required fields")


def session_management_page(api_base_url: str):
    st.header("🔑 Session Management")
    
    # Session management tabs
    tab1, tab2 = st.tabs(["Active Sessions", "Session Analytics"])
    
    with tab1:
        st.subheader("📋 Active Sessions")
        
        if st.button("Refresh Sessions"):
            try:
                # This would call the actual API endpoint
                # response = requests.get(f"{api_base_url}/sessions")
                
                # Sample sessions data
                sessions_data = {
                    "sessions": [
                        {
                            "id": "session_1",
                            "user_id": "1",
                            "username": "admin",
                            "client_ip": "192.168.1.100",
                            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "created_at": "2024-01-01T10:00:00Z",
                            "expires_at": "2024-01-01T11:00:00Z",
                            "last_activity": "2024-01-01T10:30:00Z"
                        },
                        {
                            "id": "session_2",
                            "user_id": "2",
                            "username": "user1",
                            "client_ip": "192.168.1.101",
                            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                            "created_at": "2024-01-01T09:30:00Z",
                            "expires_at": "2024-01-01T10:30:00Z",
                            "last_activity": "2024-01-01T10:15:00Z"
                        }
                    ]
                }
                
                if sessions_data["sessions"]:
                    sessions_df = pd.DataFrame(sessions_data["sessions"])
                    st.dataframe(sessions_df, use_container_width=True)
                    
                    # Session actions
                    st.subheader("Session Actions")
                    
                    selected_session = st.selectbox("Select Session to Manage", sessions_data["sessions"], format_func=lambda x: f"{x['username']} - {x['id']}")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button("Revoke Session"):
                            st.warning(f"Session {selected_session['id']} revoked")
                    
                    with col2:
                        if st.button("Extend Session"):
                            st.info(f"Session {selected_session['id']} extended")
                    
                    with col3:
                        if st.button("View Session Details"):
                            st.json(selected_session)
                else:
                    st.info("No active sessions found")
                
            except Exception as e:
                st.error(f"Error fetching sessions: {e}")
    
    with tab2:
        st.subheader("📊 Session Analytics")
        
        # Session statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Active Sessions", "25")
        
        with col2:
            st.metric("Sessions Created Today", "15")
        
        with col3:
            st.metric("Average Session Duration", "45 min")
        
        with col4:
            st.metric("Sessions Expired Today", "8")
        
        # Session trends
        st.subheader("📈 Session Trends")
        
        # Sample session data over time
        dates = pd.date_range(start='2024-01-01', end='2024-01-07', freq='D')
        session_counts = [20, 25, 30, 28, 35, 32, 25]
        
        fig = px.line(
            x=dates,
            y=session_counts,
            title="Active Sessions Over Time",
            labels={'x': 'Date', 'y': 'Active Sessions'}
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Session duration distribution
        st.subheader("⏱️ Session Duration Distribution")
        
        duration_data = {
            "Duration Range": ["0-15 min", "15-30 min", "30-60 min", "1-2 hours", "2+ hours"],
            "Count": [5, 10, 15, 8, 2]
        }
        
        fig = px.bar(
            duration_data,
            x="Duration Range",
            y="Count",
            title="Session Duration Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)


def audit_logs_page(api_base_url: str):
    st.header("📋 Audit Logs")
    
    # Audit logs filters
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        user_id_filter = st.text_input("User ID Filter")
    
    with col2:
        action_filter = st.selectbox("Action Filter", ["All", "login", "logout", "role_assigned", "permission_granted", "password_changed"])
    
    with col3:
        start_date = st.date_input("Start Date")
    
    with col4:
        end_date = st.date_input("End Date")
    
    if st.button("Search Audit Logs"):
        try:
            # This would call the actual API endpoint
            # response = requests.get(f"{api_base_url}/audit/logs", params={
            #     "user_id": user_id_filter if user_id_filter else None,
            #     "action": action_filter if action_filter != "All" else None,
            #     "start_date": start_date.isoformat() if start_date else None,
            #     "end_date": end_date.isoformat() if end_date else None,
            #     "limit": 100
            # })
            
            # Sample audit logs
            audit_logs = {
                "logs": [
                    {
                        "id": "1",
                        "user_id": "1",
                        "username": "admin",
                        "action": "login",
                        "resource": "auth",
                        "details": {"ip": "192.168.1.100", "user_agent": "Mozilla/5.0..."},
                        "timestamp": "2024-01-01T10:00:00Z",
                        "success": True
                    },
                    {
                        "id": "2",
                        "user_id": "2",
                        "username": "user1",
                        "action": "role_assigned",
                        "resource": "rbac",
                        "details": {"role": "moderator", "assigned_by": "admin"},
                        "timestamp": "2024-01-01T09:30:00Z",
                        "success": True
                    },
                    {
                        "id": "3",
                        "user_id": "3",
                        "username": "user2",
                        "action": "login",
                        "resource": "auth",
                        "details": {"ip": "192.168.1.102", "user_agent": "Mozilla/5.0..."},
                        "timestamp": "2024-01-01T09:00:00Z",
                        "success": False
                    }
                ],
                "count": 3
            }
            
            if audit_logs["logs"]:
                logs_df = pd.DataFrame(audit_logs["logs"])
                st.dataframe(logs_df, use_container_width=True)
                
                # Audit log statistics
                st.subheader("📊 Audit Log Statistics")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Actions distribution
                    action_counts = logs_df['action'].value_counts()
                    fig = px.pie(
                        values=action_counts.values,
                        names=action_counts.index,
                        title="Actions Distribution"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # Success vs Failure
                    success_counts = logs_df['success'].value_counts()
                    fig = px.bar(
                        x=success_counts.index,
                        y=success_counts.values,
                        title="Success vs Failure",
                        labels={'x': 'Success', 'y': 'Count'}
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No audit logs found for the specified criteria")
        
        except Exception as e:
            st.error(f"Error fetching audit logs: {e}")


def security_analytics_page(api_base_url: str):
    st.header("🔒 Security Analytics")
    
    # Security metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Failed Login Attempts (24h)", "15")
    
    with col2:
        st.metric("Account Lockouts (24h)", "3")
    
    with col3:
        st.metric("Suspicious Activities", "2")
    
    with col4:
        st.metric("Security Score", "85%")
    
    # Security trends
    st.subheader("📈 Security Trends")
    
    # Sample security data
    dates = pd.date_range(start='2024-01-01', end='2024-01-07', freq='D')
    failed_logins = [5, 8, 12, 15, 10, 7, 9]
    successful_logins = [50, 55, 60, 65, 70, 68, 72]
    
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=('Failed Login Attempts', 'Successful Logins'),
        vertical_spacing=0.1
    )
    
    fig.add_trace(
        go.Scatter(x=dates, y=failed_logins, name='Failed Logins', line=dict(color='red')),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(x=dates, y=successful_logins, name='Successful Logins', line=dict(color='green')),
        row=2, col=1
    )
    
    fig.update_layout(height=600, title_text="Login Trends Over Time")
    st.plotly_chart(fig, use_container_width=True)
    
    # Risk assessment
    st.subheader("⚠️ Risk Assessment")
    
    risk_data = {
        "Risk Level": ["Low", "Medium", "High", "Critical"],
        "Count": [45, 20, 8, 2],
        "Color": ["green", "yellow", "orange", "red"]
    }
    
    fig = px.bar(
        risk_data,
        x="Risk Level",
        y="Count",
        color="Color",
        title="User Risk Distribution",
        color_discrete_map={"green": "green", "yellow": "yellow", "orange": "orange", "red": "red"}
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Security recommendations
    st.subheader("💡 Security Recommendations")
    
    recommendations = [
        {
            "priority": "High",
            "title": "Enable MFA for Admin Users",
            "description": "All administrator accounts should have multi-factor authentication enabled",
            "impact": "High"
        },
        {
            "priority": "Medium",
            "title": "Review Failed Login Attempts",
            "description": "Investigate repeated failed login attempts from IP 192.168.1.105",
            "impact": "Medium"
        },
        {
            "priority": "Low",
            "title": "Update Password Policy",
            "description": "Consider implementing stronger password requirements",
            "impact": "Low"
        }
    ]
    
    for rec in recommendations:
        with st.expander(f"{rec['priority']} Priority: {rec['title']}"):
            st.write(f"**Description:** {rec['description']}")
            st.write(f"**Impact:** {rec['impact']}")
            
            if st.button(f"Implement {rec['title']}", key=f"implement_{rec['title']}"):
                st.success(f"Recommendation '{rec['title']}' implemented")


if __name__ == "__main__":
    main()

