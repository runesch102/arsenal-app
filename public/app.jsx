const { useState } = React;

const severityColor = {
  critical: '#ff4444',
  high:     '#ff8c00',
  medium:   '#ffd700',
  low:      '#4caf50',
};

function SeverityBadge({ level }) {
  return (
    <span style={{
      background: severityColor[level] || '#888',
      color: '#000',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 12,
      fontWeight: 700,
      textTransform: 'uppercase',
    }}>
      {level}
    </span>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: '#141a2a',
      border: '1px solid #1e2940',
      borderRadius: 8,
      padding: '16px 20px',
      textAlign: 'center',
      minWidth: 100,
    }}>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || '#4fc3f7' }}>{value}</div>
      <div style={{ fontSize: 12, color: '#8892a4', marginTop: 4 }}>{label}</div>
    </div>
  );
}

/* AttackPlanPanel – renders the full attack plan when visible */
function AttackPlanPanel({ attackPlan }) {
  if (!attackPlan) return null;

  return (
    <div>
      {/* Summary cards */}
      <h2 style={{ fontSize: 18, color: '#4fc3f7', marginBottom: 12 }}>Opsummering</h2>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 28 }}>
        <StatCard label="Hosts"    value={attackPlan.summary.totalHosts} />
        <StatCard label="Attacks"  value={attackPlan.summary.totalAttacks} />
        <StatCard label="Critical" value={attackPlan.summary.critical} color="#ff4444" />
        <StatCard label="High"     value={attackPlan.summary.high}     color="#ff8c00" />
        <StatCard label="Medium"   value={attackPlan.summary.medium}   color="#ffd700" />
        <StatCard label="Low"      value={attackPlan.summary.low}      color="#4caf50" />
      </div>

      {/* Host info */}
      <h2 style={{ fontSize: 18, color: '#4fc3f7', marginBottom: 12 }}>Hosts</h2>
      {attackPlan.hosts.map((host, i) => (
        <div key={i} style={{
          background: '#141a2a', border: '1px solid #1e2940',
          borderRadius: 8, padding: 16, marginBottom: 16,
        }}>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
            <strong style={{ color: '#4fc3f7' }}>{host.ip}</strong>
            <span style={{ color: '#8892a4' }}>{host.hostname}</span>
            <span style={{ color: '#5a6a84', fontSize: 13 }}>OS: {host.os}</span>
          </div>
          <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {host.ports.map(p => (
              <span key={p} style={{
                background: '#1a2236', border: '1px solid #2a3550',
                borderRadius: 4, padding: '2px 8px', fontSize: 12, color: '#8892a4',
              }}>
                :{p}
              </span>
            ))}
          </div>
        </div>
      ))}

      {/* Attack table */}
      <h2 style={{ fontSize: 18, color: '#4fc3f7', marginBottom: 12 }}>Attack Plan</h2>
      <div style={{
        background: '#141a2a', border: '1px solid #1e2940',
        borderRadius: 8, overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#1a2236' }}>
              {['#', 'Attack', 'Severity', 'Port', 'Module', 'Beskrivelse'].map(h => (
                <th key={h} style={{
                  padding: '10px 14px', textAlign: 'left',
                  fontSize: 12, color: '#5a6a84', fontWeight: 600,
                  borderBottom: '1px solid #1e2940',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {attackPlan.attacks.map(atk => (
              <tr key={atk.id} style={{ borderBottom: '1px solid #1a2236' }}>
                <td style={{ padding: '10px 14px', color: '#5a6a84', fontSize: 13 }}>{atk.id}</td>
                <td style={{ padding: '10px 14px', fontWeight: 600 }}>{atk.name}</td>
                <td style={{ padding: '10px 14px' }}><SeverityBadge level={atk.severity} /></td>
                <td style={{ padding: '10px 14px', color: '#8892a4', fontSize: 13 }}>:{atk.port}</td>
                <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontSize: 13, color: '#4fc3f7' }}>{atk.module}</td>
                <td style={{ padding: '10px 14px', color: '#8892a4', fontSize: 13 }}>{atk.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ArsenalExecTab – main component
   FIX: Added showPlan/setShowPlan state to gate AttackPlanPanel rendering. */
function ArsenalExecTab() {
  const [target, setTarget]           = useState('127.0.0.1');
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState(null);
  const [attackPlan, setAttackPlan]   = useState(null);
  const [showPlan, setShowPlan]       = useState(false);

  async function handleAnalyze() {
    setLoading(true);
    setError(null);
    setShowPlan(false);
    setAttackPlan(null);

    try {
      const res = await fetch('/api/arsenal/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });

      if (!res.ok) {
        throw new Error(`Server responded ${res.status}`);
      }

      const data = await res.json();
      setAttackPlan(data);
      setShowPlan(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 960, margin: '0 auto', padding: '32px 16px' }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, color: '#4fc3f7', marginBottom: 4 }}>
        Arsenal <span style={{ color: '#8892a4', fontWeight: 400, fontSize: 16 }}>// Attack Planner</span>
      </h1>
      <p style={{ color: '#5a6a84', marginBottom: 24, fontSize: 14 }}>
        Analysér et mål og generer en attack plan baseret på åbne porte og kendte sårbarheder.
      </p>

      <div style={{
        display: 'flex', gap: 12, marginBottom: 24,
        background: '#141a2a', border: '1px solid #1e2940',
        borderRadius: 8, padding: 16,
      }}>
        <input
          type="text"
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="Target IP / hostname"
          style={{
            flex: 1, padding: '10px 14px', borderRadius: 6,
            border: '1px solid #2a3550', background: '#0d1220',
            color: '#e0e0e0', fontSize: 15, outline: 'none',
          }}
          onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
        />
        <button
          onClick={handleAnalyze}
          disabled={loading || !target.trim()}
          style={{
            padding: '10px 28px', borderRadius: 6, border: 'none',
            background: loading ? '#2a3550' : '#4fc3f7', color: '#0a0e17',
            fontWeight: 700, fontSize: 15, cursor: loading ? 'wait' : 'pointer',
            transition: 'background .2s',
          }}
        >
          {loading ? 'Analyserer…' : 'Analysér'}
        </button>
      </div>

      {error && (
        <div style={{
          background: '#2a1015', border: '1px solid #ff4444',
          borderRadius: 8, padding: 14, marginBottom: 20, color: '#ff6b6b',
        }}>
          Fejl: {error}
        </div>
      )}

      {showPlan && <AttackPlanPanel attackPlan={attackPlan} />}
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<ArsenalExecTab />);
