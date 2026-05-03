import React, { useState, useEffect, useCallback } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import {
    LayoutDashboard, ShieldCheck,
    Sun, Moon, User, Bell, Settings, Users as UsersIcon,
    ArrowLeft, Activity, Server, Smartphone, Globe, List
} from "lucide-react";
import "../Dashboard.css";

const BASE_URL = "http://localhost:8001/api";

const Visual = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const user = location.state?.user;
    const [theme, setTheme] = useState(document.body.getAttribute('data-theme') || 'light');

    const username = "AI_firewall";

    // --- Live data state ---
    const [summary, setSummary] = useState(null);
    const [analytics, setAnalytics] = useState(null);
    const [logs, setLogs] = useState([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const LIMIT = 10;

    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const fetchAll = useCallback(async (currentPage = 1) => {
        const uid = user?.user_id || user?.id;
        if (!uid) return;

        setLoading(true);
        setError("");

        try {
            const headers = { "Content-Type": "application/json" };

            const [sumRes, anaRes, logsRes] = await Promise.all([
                fetch(`${BASE_URL}/user/summary/?user_id=${uid}`, { headers }),
                fetch(`${BASE_URL}/user/analytics/?user_id=${uid}`, { headers }),
                fetch(`${BASE_URL}/user/logs/?user_id=${uid}&page=${currentPage}&limit=${LIMIT}`, { headers }),
            ]);

            if (sumRes.ok) setSummary(await sumRes.json());
            else setError("Failed to load user summary.");

            if (anaRes.ok) setAnalytics(await anaRes.json());

            if (logsRes.ok) {
                const logsData = await logsRes.json();
                setLogs(logsData.results || []);
                setTotal(logsData.count || 0);
            }
        } catch (err) {
            setError("Failed to load analytics data. Is the backend running?");
        } finally {
            setLoading(false);
        }
    }, [user]);

    useEffect(() => {
        fetchAll(page);
    }, [fetchAll, page]);

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        document.body.setAttribute('data-theme', newTheme);
    };

    if (!user) {
        return (
            <div className="dashboard-layout" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
                <div style={{ textAlign: 'center' }}>
                    <h2 style={{ marginBottom: '16px' }}>No user selected</h2>
                    <button className="dash-btn" onClick={() => navigate("/users")}>Go back to Users</button>
                </div>
            </div>
        )
    }

    const totalPages = Math.ceil(total / LIMIT);


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
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <button
                            onClick={() => navigate("/users")}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '6px', display: 'flex', alignItems: 'center', color: 'var(--text-secondary)' }}
                        >
                            <ArrowLeft size={24} />
                        </button>
                        <div>
                            <h1 className="h1">{user.name}</h1>
                            <p className="micro-label" style={{ marginTop: '4px', fontSize: '13px', color: 'var(--text-secondary)', fontWeight: '600' }}>
                                User Analytics • {user.email}
                            </p>
                        </div>
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

                {error && (
                    <div className="dash-error" style={{ marginBottom: '16px' }}>{error}</div>
                )}

                {loading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px', color: 'var(--text-secondary)', fontSize: '15px' }}>
                        Loading analytics…
                    </div>
                ) : (
                    <>
                        {/* KPI Cards Row */}
                        <div className="stats-row">
                            <div className="stat-card accent-green">
                                <p className="stat-label">Requests / Day</p>
                                <p className="stat-value" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <Activity size={24} color="var(--success-green)" />
                                    {summary?.requests_per_day ?? "—"}
                                </p>
                            </div>
                            <div className="stat-card accent-orange">
                                <p className="stat-label">Avg Risk Score</p>
                                <p className="stat-value" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <Server size={24} color="#f59e0b" />
                                    {summary?.avg_risk_score ?? "—"}
                                </p>
                            </div>
                            <div className="stat-card accent-red">
                                <p className="stat-label">Frequency Interval</p>
                                <p className="stat-value" style={{ fontSize: '24px', color: 'var(--alert-red)' }}>
                                    {summary?.frequency_interval ?? "—"}
                                </p>
                            </div>
                        </div>

                        {/* Top Statistics Lists */}
                        <div className="bento-grid" style={{ marginBottom: '24px' }}>
                            <div className="bento-card col-span-4">
                                <h3 className="h3" style={{ fontSize: '15px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                                    <Globe size={18} /> Top IPs
                                </h3>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                    {(analytics?.top_ips ?? []).length === 0
                                        ? <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>No data yet</p>
                                        : (analytics?.top_ips ?? []).map((ip, i) => (
                                            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', backgroundColor: 'var(--input-bg)', borderRadius: '6px' }}>
                                                <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{ip.ip}</span>
                                                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)' }}>{ip.count} reqs</span>
                                            </div>
                                        ))
                                    }
                                </div>
                            </div>

                            <div className="bento-card col-span-4">
                                <h3 className="h3" style={{ fontSize: '15px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                                    <Server size={18} /> Most Used Endpoints
                                </h3>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                    {(analytics?.top_endpoints ?? []).length === 0
                                        ? <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>No data yet</p>
                                        : (analytics?.top_endpoints ?? []).map((e, i) => (
                                            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', backgroundColor: 'var(--input-bg)', borderRadius: '6px' }}>
                                                <span style={{ fontFamily: 'monospace', color: 'var(--primary-navy)' }}>{e.endpoint}</span>
                                                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)' }}>{e.count} reqs</span>
                                            </div>
                                        ))
                                    }
                                </div>
                            </div>

                            <div className="bento-card col-span-4">
                                <h3 className="h3" style={{ fontSize: '15px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                                    <Smartphone size={18} /> Most Used Devices
                                </h3>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                    {(analytics?.top_devices ?? []).length === 0
                                        ? <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>No data yet</p>
                                        : (analytics?.top_devices ?? []).map((d, i) => (
                                            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', backgroundColor: 'var(--input-bg)', borderRadius: '6px' }}>
                                                <span style={{ fontWeight: 600 }}>{d.device}</span>
                                                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)' }}>{d.count} sessions</span>
                                            </div>
                                        ))
                                    }
                                </div>
                            </div>
                        </div>

                        {/* System Logs */}
                        <div className="dash-card">
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <h2><List size={20} style={{ verticalAlign: 'middle', marginRight: '8px' }} /> System Logs History</h2>
                                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                                    {total} total • Page {page} of {totalPages || 1}
                                </span>
                            </div>
                            <table className="dash-table" style={{ marginTop: '16px' }}>
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Device</th>
                                        <th>Endpoint</th>
                                        <th>Attack Type</th>
                                        <th>Decision</th>
                                        <th>Risk Score</th>
                                        <th>Timestamp</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {logs.length === 0 ? (
                                        <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '24px' }}>No logs found</td></tr>
                                    ) : (
                                        logs.map((log, i) => (
                                            <tr key={i}>
                                                <td style={{ fontFamily: "monospace" }}>{log.ip || "—"}</td>
                                                <td>{log.device || "—"}</td>
                                                <td style={{ fontFamily: "monospace", color: "var(--primary-navy)" }}>{log.endpoint || "—"}</td>
                                                <td style={{ fontSize: '12px', fontFamily: 'monospace' }}>{log.attack_type || "—"}</td>
                                                <td>
                                                    <span className={`mode-badge ${log.decision === "block" ? "attack" : log.decision === "sanitize" ? "warning" : "normal"}`} style={{ padding: '2px 8px', borderRadius: '12px' }}>
                                                        {log.decision || "—"}
                                                    </span>
                                                </td>
                                                <td>
                                                    <span className={`mode-badge ${log.risk_score > 70 ? "attack" : log.risk_score > 40 ? "warning" : "normal"}`} style={{ padding: '2px 8px', borderRadius: '12px' }}>
                                                        {log.risk_score ?? "—"}
                                                    </span>
                                                </td>
                                                <td style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>{log.timestamp}</td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>

                            {totalPages > 1 && (
                                <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '16px' }}>
                                    <button
                                        className="dash-btn-secondary"
                                        onClick={() => setPage(p => Math.max(1, p - 1))}
                                        disabled={page === 1}
                                        style={{ padding: '6px 16px', fontSize: '13px' }}
                                    >
                                        ← Prev
                                    </button>
                                    <span style={{ lineHeight: '32px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                                        {page} / {totalPages}
                                    </span>
                                    <button
                                        className="dash-btn-secondary"
                                        onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                                        disabled={page === totalPages}
                                        style={{ padding: '6px 16px', fontSize: '13px' }}
                                    >
                                        Next →
                                    </button>
                                </div>
                            )}
                        </div>
                    </>
                )}

            </main>
        </div>
    );
};

export default Visual;
