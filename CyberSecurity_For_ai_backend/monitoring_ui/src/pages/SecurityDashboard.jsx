import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { apiRequest } from "../utils/api";
import {
    LayoutDashboard, ShieldCheck,
    Sun, Moon, User, Bell, Settings, Users as UsersIcon
} from "lucide-react";
import "../Dashboard.css";


const SecurityDashboard = () => {
    const [sessions, setSessions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [theme, setTheme] = useState(document.body.getAttribute('data-theme') || 'light');

    const username = "AI_firewall";

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        document.body.setAttribute('data-theme', newTheme);
    };

    useEffect(() => {
        const fetchSessions = async () => {
            const res = await apiRequest("/sessions/", "GET");
            if (Array.isArray(res)) {
                setSessions(res);
            } else if (res && !res._error) {
                setSessions([]);
            }
            setLoading(false);
        };
        fetchSessions();
        const interval = setInterval(fetchSessions, 5000);
        return () => clearInterval(interval);
    }, []);


    const getRiskClass = (risk) => {
        if (risk > 70) return "risk-high";
        if (risk > 40) return "risk-medium";
        return "risk-low";
    };

    const getDecisionBadge = (decision) => {
        if (decision === "block") return "attack";
        if (decision === "sanitize") return "warning";
        return "normal";
    };

    const activeSessions = sessions.filter(s => s.status === "active").length;
    const blockedSessions = sessions.filter(s => s.status === "blocked").length;


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
                    <Link to="/security" className="sidebar-link active">
                        <LayoutDashboard size={20} className="link-icon" />
                        <span>Sessions</span>
                    </Link>
                    <Link to="/alerts" className="sidebar-link">
                        <Bell size={20} className="link-icon" />
                        <span>Alerts</span>
                    </Link>
                    <Link to="/users" className="sidebar-link">
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
                        <h1 className="h1">Welcome, {username}.</h1>
                        <p className="micro-label" style={{ marginTop: '8px' }}>System Monitoring Dashboard</p>
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

                <div className="stats-row">
                    <div className="stat-card">
                        <p className="stat-label">Total Sessions</p>
                        <p className="stat-value">{sessions.length}</p>
                    </div>
                    <div className="stat-card accent-green">
                        <p className="stat-label">Active</p>
                        <p className="stat-value">{activeSessions}</p>
                    </div>
                    <div className="stat-card accent-red">
                        <p className="stat-label">Blocked</p>
                        <p className="stat-value">{blockedSessions}</p>
                    </div>
                </div>

                <div className="dash-card">
                    <h2><LayoutDashboard size={20} style={{ verticalAlign: 'middle', marginRight: '8px' }} /> Active Sessions</h2>
                    {loading ? (
                        <div className="empty-state">Loading sessions...</div>
                    ) : sessions.length === 0 ? (
                        <div className="empty-state">No sessions found. Send a message in the chatbot to generate logs.</div>
                    ) : (
                        <table className="dash-table" style={{ marginTop: '16px' }}>
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>IP Address</th>
                                    <th>Endpoint</th>
                                    <th>Attack Type</th>
                                    <th>Decision</th>
                                    <th>Risk Score</th>
                                    <th>Status</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                                {sessions.map((s, index) => (
                                    <tr key={index}>
                                        <td style={{ fontWeight: 600 }}>{s.user}</td>
                                        <td>{s.ip_address}</td>
                                        <td style={{ fontFamily: 'monospace', color: 'var(--primary-navy)', fontSize: '12px' }}>{s.endpoint}</td>
                                        <td style={{ fontSize: '12px', fontFamily: 'monospace' }}>{s.attack_type}</td>
                                        <td>
                                            <span className={`mode-badge ${getDecisionBadge(s.decision)}`}>
                                                {s.decision}
                                            </span>
                                        </td>
                                        <td className={getRiskClass(s.risk_score)}>{s.risk_score}</td>
                                        <td>
                                            <span className={`mode-badge ${s.status === "active" ? "normal" : "attack"}`}>
                                                {s.status}
                                            </span>
                                        </td>
                                        <td style={{ color: "var(--text-secondary)", fontSize: "0.82rem" }}>
                                            {new Date(s.created_at).toLocaleString()}
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

export default SecurityDashboard;
