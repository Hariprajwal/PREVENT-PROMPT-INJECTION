import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { apiRequest } from "../utils/api";
import {
    LayoutDashboard, ShieldCheck,
    Sun, Moon, User, Bell, Settings, Users as UsersIcon
} from "lucide-react";
import "../Dashboard.css";


const Alerts = () => {
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [theme, setTheme] = useState(document.body.getAttribute('data-theme') || 'light');

    const username = "AI_firewall";

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        document.body.setAttribute('data-theme', newTheme);
    };

    useEffect(() => {
        const fetchAlerts = async () => {
            const res = await apiRequest("/alerts/", "GET");
            if (Array.isArray(res)) {
                setAlerts(res);
            }
            setLoading(false);
        };
        fetchAlerts();
        const interval = setInterval(fetchAlerts, 5000);
        return () => clearInterval(interval);
    }, []);

    const highRisk = alerts.filter(a => a.risk_score > 70).length;
    const mediumRisk = alerts.filter(a => a.risk_score > 40 && a.risk_score <= 70).length;

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
                    <Link to="/alerts" className="sidebar-link active">
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
                        <p className="micro-label" style={{ marginTop: '8px' }}>Security Incident Alerts</p>
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
                    <div className="stat-card accent-red">
                        <p className="stat-label">High Risk</p>
                        <p className="stat-value">{highRisk}</p>
                    </div>
                    <div className="stat-card accent-orange">
                        <p className="stat-label">Medium Risk</p>
                        <p className="stat-value">{mediumRisk}</p>
                    </div>
                    <div className="stat-card">
                        <p className="stat-label">Total Alerts</p>
                        <p className="stat-value">{alerts.length}</p>
                    </div>
                </div>

                {loading ? (
                    <div className="dash-card">
                        <div className="empty-state">Loading alerts...</div>
                    </div>
                ) : alerts.length === 0 ? (
                    <div className="dash-card">
                        <div className="empty-state">✅ No security alerts — all clear!</div>
                    </div>
                ) : (
                    alerts.map((alert, index) => (
                        <div className="alert-card" key={index} style={{ marginBottom: '16px', background: 'var(--surface-card)', padding: '24px', borderRadius: 'var(--radius-soft)', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}>
                            <h3 style={{ margin: '0 0 12px 0', fontSize: '16px' }}>⚠️ Security Alert</h3>
                            <p style={{ margin: '4px 0' }}><b>User:</b> {alert.user}</p>
                            <p style={{ margin: '4px 0' }}><b>Attack Type:</b> <span style={{ fontFamily: 'monospace', color: 'var(--alert-red)' }}>{alert.attack_type}</span></p>
                            <p style={{ margin: '4px 0' }}><b>Decision:</b> <span className={`mode-badge ${alert.decision === "block" ? "attack" : "warning"}`} style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '12px' }}>{alert.decision}</span></p>
                            <p style={{ margin: '4px 0' }}><b>IP:</b> {alert.ip}</p>
                            <p style={{ margin: '4px 0' }}><b>Device:</b> {alert.device}</p>
                            <p style={{ margin: '4px 0' }}>
                                <b>Risk Score: </b>
                                <span className={
                                    alert.risk_score > 70 ? "risk-high" :
                                        alert.risk_score > 40 ? "risk-medium" : "risk-low"
                                } style={{ padding: '2px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: 'bold' }}>{alert.risk_score}</span>
                            </p>
                            <p style={{ margin: '4px 0' }}><b>Reason:</b> {alert.reason}</p>
                            {alert.user_input && (
                                <p style={{ margin: '4px 0', fontFamily: 'monospace', fontSize: '12px', color: 'var(--text-secondary)', background: 'var(--input-bg)', padding: '8px 12px', borderRadius: '8px', marginTop: '8px' }}>
                                    <b>Input:</b> {alert.user_input}
                                </p>
                            )}
                            <p style={{ color: "var(--text-secondary)", fontSize: "0.82rem", marginTop: '12px', marginBottom: 0 }}>
                                {new Date(alert.timestamp).toLocaleString()}
                            </p>
                        </div>
                    ))
                )}
            </main>
        </div>
    );
};

export default Alerts;
