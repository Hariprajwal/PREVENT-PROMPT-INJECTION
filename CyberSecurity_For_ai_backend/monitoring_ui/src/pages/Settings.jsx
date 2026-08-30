import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
    LayoutDashboard, ShieldCheck,
    Sun, Moon, User, Bell, Settings as SettingsIcon, Users as UsersIcon,
    Fingerprint
} from "lucide-react";
import "../Dashboard.css";

const Settings = () => {
    const [theme, setTheme] = useState(document.body.getAttribute('data-theme') || 'light');
    const username = "AI_firewall";

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        document.body.setAttribute('data-theme', newTheme);
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
                    <Link to="/users" className="sidebar-link">
                        <UsersIcon size={20} className="link-icon" />
                        <span>Users</span>
                    </Link>
                    <Link to="/security-settings" className="sidebar-link active">
                        <SettingsIcon size={20} className="link-icon" />
                        <span>Settings</span>
                    </Link>
                </nav>
            </aside>

            <main className="main-content">
                <div className="main-header" style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                        <h1 className="h1">Settings</h1>
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

                <div className="bento-grid">
                    <div className="bento-card col-span-8">
                        <h2><Fingerprint size={20} /> System Details</h2>
                        <div style={{ display: 'flex', gap: '48px', marginBottom: '32px' }}>
                            <div>
                                <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: '700' }}>Username</label>
                                <p style={{ margin: '8px 0 0 0', fontSize: '16px', fontWeight: '600', color: 'var(--primary-navy)' }}>{username}</p>
                            </div>
                            <div>
                                <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: '700' }}>Service Status</label>
                                <p style={{ margin: '8px 0 0 0', fontSize: '16px', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--success-green)' }}>
                                    <ShieldCheck size={18} /> Active — Monitoring
                                </p>
                            </div>
                        </div>

                        <hr style={{ border: 'none', borderTop: '1px solid var(--input-bg)', margin: '0 0 24px 0' }} />

                        <h2>Configuration</h2>
                        <div style={{ marginTop: '16px' }}>
                            <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
                                <b>Chatbot API:</b> http://localhost:8008/api/chat
                            </p>
                            <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
                                <b>Monitoring API:</b> http://localhost:8001/api
                            </p>
                            <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
                                <b>ML Model:</b> Isolation Forest (anomaly_detection.py)
                            </p>
                            <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
                                <b>Security Level:</b> Fast (regex-based)
                            </p>
                            <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
                                <b>LLM Model:</b> Ollama Gemma:2B
                            </p>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
};

export default Settings;
