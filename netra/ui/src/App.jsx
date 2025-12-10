import React, { useState } from 'react';
import { Shield, Activity, Server, AlertTriangle, CheckCircle, Terminal } from 'lucide-react';
import { motion } from 'framer-motion';

function App() {
    const [target, setTarget] = useState('');
    const [scanning, setScanning] = useState(false);
    const [results, setResults] = useState(null);
    const [logs, setLogs] = useState([]);

    const addLog = (msg) => setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);

    const startScan = async () => {
        if (!target) return;
        setScanning(true);
        setResults(null);
        setLogs([]);
        addLog(`Initiating scan for ${target}...`);

        try {
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target }),
            });

            if (!response.ok) throw new Error('Failed to start scan');

            addLog('Scan job submitted successfully.');
            addLog('Waiting for results...');

            // Poll for results (simplified for MVP)
            const pollInterval = setInterval(async () => {
                try {
                    const res = await fetch(`/api/scan/results/${encodeURIComponent(target)}`);
                    const resData = await res.json();

                    if (resData.status !== 'pending or not found') {
                        clearInterval(pollInterval);
                        setResults(resData);
                        setScanning(false);
                        addLog('Scan completed.');
                    }
                } catch (e) {
                    console.error(e);
                }
            }, 1000);

            // Timeout after 30s
            setTimeout(() => {
                clearInterval(pollInterval);
                if (scanning) {
                    setScanning(false);
                    addLog('Scan timed out.');
                }
            }, 30000);

        } catch (e) {
            console.error(e);
            addLog(`Error: ${e.message}`);
            setScanning(false);
        }
    };

    return (
        <div className="min-h-screen bg-slate-950 text-white font-sans selection:bg-blue-500/30">
            {/* Header */}
            <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-gradient-to-br from-blue-600 to-violet-600 rounded-lg shadow-lg shadow-blue-500/20">
                            <Shield className="w-6 h-6 text-white" />
                        </div>
                        <div>
                            <h1 className="text-xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
                                Vortex Platform
                            </h1>
                            <p className="text-xs text-slate-500 font-mono">v1.0.0-alpha</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800">
                            <div className={`w-2 h-2 rounded-full ${scanning ? 'bg-green-500 animate-pulse' : 'bg-slate-500'}`} />
                            <span className="text-xs font-medium text-slate-400">{scanning ? 'System Active' : 'System Idle'}</span>
                        </div>
                    </div>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-6 py-12">
                {/* Hero / Input Section */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="max-w-3xl mx-auto text-center mb-16"
                >
                    <h2 className="text-4xl md:text-5xl font-bold mb-6 bg-gradient-to-r from-blue-400 via-violet-400 to-fuchsia-400 bg-clip-text text-transparent">
                        Next-Generation Vulnerability Engine
                    </h2>
                    <p className="text-slate-400 text-lg mb-8">
                        Perform deep async reconnaissance and vulnerability analysis with zero-latency feedback.
                    </p>

                    <div className="relative group">
                        <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-violet-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
                        <div className="relative flex gap-2 bg-slate-900 p-2 rounded-xl border border-slate-800 shadow-2xl">
                            <div className="flex-1 flex items-center gap-3 px-4 bg-slate-950/50 rounded-lg border border-slate-800/50 focus-within:border-blue-500/50 transition-colors">
                                <Terminal className="w-5 h-5 text-slate-500" />
                                <input
                                    type="text"
                                    placeholder="Enter target (e.g., scanme.nmap.org)"
                                    className="flex-1 bg-transparent py-4 outline-none text-slate-200 placeholder:text-slate-600 font-mono"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && startScan()}
                                />
                            </div>
                            <button
                                onClick={startScan}
                                disabled={scanning || !target}
                                className="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 text-white px-8 rounded-lg font-semibold transition-all shadow-lg shadow-blue-500/20 flex items-center gap-2"
                            >
                                {scanning ? <Activity className="animate-spin w-5 h-5" /> : <Server className="w-5 h-5" />}
                                <span>{scanning ? 'Scanning' : 'Launch'}</span>
                            </button>
                        </div>
                    </div>
                </motion.div>

                {/* Dashboard Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* Live Logs */}
                    <motion.div
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="lg:col-span-1 bg-slate-900/50 border border-slate-800 rounded-xl p-6 backdrop-blur-sm flex flex-col h-[500px]"
                    >
                        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                            <Terminal className="w-5 h-5 text-blue-400" />
                            Live Operation Logs
                        </h3>
                        <div className="flex-1 overflow-auto font-mono text-xs space-y-2 text-slate-400 p-4 bg-slate-950 rounded-lg border border-slate-800/50">
                            {logs.length === 0 && <span className="text-slate-600 italic">Waiting for operations...</span>}
                            {logs.map((log, i) => (
                                <div key={i} className="border-l-2 border-blue-500/30 pl-2">{log}</div>
                            ))}
                        </div>
                    </motion.div>

                    {/* Results Area */}
                    <motion.div
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-xl p-6 backdrop-blur-sm h-[500px] overflow-auto"
                    >
                        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                            <Activity className="w-5 h-5 text-violet-400" />
                            Scan Results
                        </h3>

                        {!results ? (
                            <div className="h-full flex flex-col items-center justify-center text-slate-600">
                                <div className="w-16 h-16 border-4 border-slate-800 border-t-blue-500 rounded-full animate-spin mb-4 opacity-20"></div>
                                <p>No results to display</p>
                            </div>
                        ) : (
                            <div className="space-y-6">
                                {/* Network Module Results */}
                                {results.PortScanner && (
                                    <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
                                        <h4 className="text-sm font-medium text-slate-400 mb-3 uppercase tracking-wider">Open Ports</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {results.PortScanner.open_ports?.map(port => (
                                                <span key={port} className="px-3 py-1 bg-green-500/10 text-green-400 border border-green-500/20 rounded-md text-sm font-mono">
                                                    {port}/TCP
                                                </span>
                                            ))}
                                            {(!results.PortScanner.open_ports || results.PortScanner.open_ports.length === 0) && (
                                                <span className="text-slate-500 text-sm">No open ports found.</span>
                                            )}
                                        </div>
                                    </div>
                                )}

                                {/* HTTP Module Results */}
                                {results.HTTPScanner && (
                                    <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
                                        <h4 className="text-sm font-medium text-slate-400 mb-3 uppercase tracking-wider">HTTP Analysis</h4>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div className="p-3 bg-slate-900 rounded border border-slate-800">
                                                <span className="text-xs text-slate-500 block">Server</span>
                                                <span className="text-sm font-mono text-blue-300">{results.HTTPScanner.server || 'Unknown'}</span>
                                            </div>
                                            <div className="p-3 bg-slate-900 rounded border border-slate-800">
                                                <span className="text-xs text-slate-500 block">Status</span>
                                                <span className="text-sm font-mono text-green-300">{results.HTTPScanner.status_code || 'N/A'}</span>
                                            </div>
                                        </div>

                                        {results.HTTPScanner.tech_stack && results.HTTPScanner.tech_stack.length > 0 && (
                                            <div className="mt-4">
                                                <span className="text-xs text-slate-500 block mb-2">Detected Tech</span>
                                                <div className="flex gap-2">
                                                    {results.HTTPScanner.tech_stack.map((tech, i) => (
                                                        <span key={i} className="px-2 py-1 bg-violet-500/10 text-violet-400 border border-violet-500/20 rounded text-xs">
                                                            {tech}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        )}
                    </motion.div>
                </div>
            </main>
        </div>
    );
}

export default App;
