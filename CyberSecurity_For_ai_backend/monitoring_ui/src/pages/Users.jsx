import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
    LayoutDashboard, ShieldCheck,
    Sun, Moon, User, Bell, Settings, Users as UsersIcon
} from "lucide-react";
import "../Dashboard.css";
import { apiRequest } from "../utils/api";

const Users = () => {
    const navigate = useNavigate();
    const [theme, setTheme] = useState(document.body.getAttribute('data-theme') || 'light');
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const username = "AI_firewall";

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const res = await apiRequest("/users-list/", "GET");
                if (res.data) {
                    setUsers(res.data);
                } else if (res._error) {
                    setError("Failed to fetch users.");
                }
            } catch (err) {
                setError("Failed to fetch users.");
            } finally {
                setLoading(false);
            }
        };
        fetchUsers();
    }, []);

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        document.body.setAttribute('data-theme', newTheme);
    };

    const goToDetails = (user) => {
        navigate("/visual", { state: { user: { ...user, id: user.user_id, name: user.username } } });
    };


    return (
        <div className="dashboard-layout">
            <aside className="sidebar">
                <div className="sidebar-header">
                    <h2><ShieldCheck size={28} /> AI Firewall</h2>
                    <div className="sidebar-role" style={{ color: 'var(--text-secondary)' }}>
                        Monitoring Console
                    </div>
                </div>
                <nav className="sidebar-nav">
                    <Link to="/security" className="sidebar-link">
                        <LayoutDashboard size={20} className="link-icon" />
                        <span>Sessions</span>
                    </Link>
                    <Link to="/alerts" className="sidebar-link">
                        <Bell size={20} className="link-icon" />
                        <span>Alerts</span>
                    </Link>
                    <Link to="/users" className="sidebar-link active">
                        <UsersIcon size={20} className="link-icon" />
                        <span>Users</span>
                    </Link>
                    <Link to="/security-settings" className="sidebar-link">
                        <Settings size={20} className="link-icon" />
                        <span>Settings</span>
                    </Link>
                </nav>
            </aside>

            <main className="main-content">
                <div className="main-header" style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                        <h1 className="h1">Chatbot Users</h1>
                        <p className="micro-label" style={{ marginTop: '8px' }}>Monitored Services</p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        <button onClick={toggleTheme} className="dash-btn-secondary" style={{ padding: '8px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', width: '40px', height: '40px', border: 'none', backgroundColor: 'var(--input-bg)', cursor: 'pointer' }}>
                            {theme === 'light' ? <Moon size={20} color="var(--primary-navy)" /> : <Sun size={20} color="var(--primary-navy)" />}
                        </button>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '6px 16px 6px 6px', borderRadius: '30px', backgroundColor: 'var(--input-bg)' }}>
                            <div style={{ width: '36px', height: '36px', borderRadius: '50%', backgroundColor: 'var(--primary-navy)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <User size={18} />
                            </div>
                            <span style={{ fontWeight: 600, fontSize: '14px', color: 'var(--text-primary)' }}>{username}</span>
                        </div>
                    </div>
                </div>

                <div className="dash-card">
                    <h2><UsersIcon size={20} style={{ verticalAlign: 'middle', marginRight: '8px' }} /> Registered Services</h2>

                    {loading ? (
                        <div className="empty-state">Loading users...</div>
                    ) : error ? (
                        <div className="empty-state" style={{ color: "var(--alert-red)" }}>{error}</div>
                    ) : users.length === 0 ? (
                        <div className="empty-state">No users registered yet.</div>
                    ) : (
                        <table className="dash-table" style={{ marginTop: '16px' }}>
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Last Login</th>
                                    <th>Joined At</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {users.map((u) => (
                                    <tr key={u.user_id}>
                                        <td style={{ fontWeight: 600 }}>{u.username}</td>
                                        <td>{u.email}</td>
                                        <td style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>{u.last_login}</td>
                                        <td style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>{u.joined_at}</td>
                                        <td>
                                            <button
                                                className="dash-btn"
                                                style={{ padding: '6px 12px', fontSize: '12px', background: '#3b82f6', boxShadow: '0 2px 8px rgba(59, 130, 246, 0.3)', minWidth: '80px', margin: '0 auto' }}
                                                onClick={() => goToDetails(u)}
                                            >
                                                In-Detail
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>

            </main>
        </div>
    );
};

export default Users;
