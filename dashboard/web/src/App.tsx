import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import type { Action, BaitFile, Event, Job, LiveResponse, RuleFile, RuleRecord, Service, Session, ServicesResponse } from './types'
import { ArrowIcon, BaitIcon, ChevronIcon, CloseIcon, ExternalIcon, OverviewIcon, PlayIcon, RefreshIcon, RulesIcon, SessionsIcon, SettingsIcon, ShieldIcon } from './icons'
import { CommandCenter } from './CommandCenter'

type View = 'overview' | 'sessions' | 'bait' | 'rules'

const navItems: { id: View; label: string; icon: typeof OverviewIcon }[] = [
  { id: 'overview', label: 'Command Center', icon: OverviewIcon },
  { id: 'sessions', label: 'Investigate', icon: SessionsIcon },
  { id: 'bait', label: 'Deception', icon: BaitIcon },
  { id: 'rules', label: 'Detection', icon: RulesIcon },
]

function formatTime(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function relativeTime(value?: string) {
  if (!value) return 'No recent activity'
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000))
  if (seconds < 5) return 'Just now'
  if (seconds < 60) return `${seconds}s ago`
  return `${Math.floor(seconds / 60)}m ago`
}

function profileLabel(profile?: string) {
  const labels: Record<string, string> = {
    scriptkiddie: 'Script Kiddie',
    opportunist: 'Opportunist',
    targeted: 'Targeted',
  }
  return profile ? labels[profile] ?? profile : 'Unknown profile'
}

const attackerProfiles = [
  {
    id: 'scriptkiddie',
    label: 'Script Kiddie',
    index: '01',
    summary: 'Fast, noisy, and shallow by design.',
    detail: 'Makes four credential attempts, then runs five familiar reconnaissance commands after access.',
    signal: 'Broad reconnaissance',
    credentialPlan: '4 attempts · 5 post-login commands',
  },
  {
    id: 'opportunist',
    label: 'Opportunist',
    index: '02',
    summary: 'Looks for credentials, sensitive files, and an easy opening.',
    detail: 'Makes five credential attempts, then runs eleven recon, sensitive-file, and payload-download commands after access.',
    signal: 'Credential harvesting',
    credentialPlan: '5 attempts · 11 post-login commands',
  },
  {
    id: 'targeted',
    label: 'Targeted',
    index: '03',
    summary: 'Slow, deliberate, and deeper in scope.',
    detail: 'Makes three credential attempts, then runs nineteen configuration, persistence, and discovery commands after access.',
    signal: 'Objective-driven access',
    credentialPlan: '3 attempts · 19 post-login commands',
  },
]

function stageFor(live: LiveResponse | null) {
  if (!live?.session && !live?.attack) return 0
  const session = live.session ?? {}
  const events = live.events ?? []
  const joined = (session.commands ?? []).join(' ').toLowerCase()
  const types = new Set(events.map((event) => event.event_type))
  const phase = live.attack?.phase
  if (phase === 'completed') return 6
  if (phase === 'generating_rules') return 6
  if (phase === 'waiting_for_action') return 5
  if (phase === 'processing_events') return 4
  if (phase === 'running_attack' && !events.length) return 1
  if (live.rules.length) return 6
  if (live.actions.length) return 5
  if (/\/etc\/passwd|\/etc\/shadow|\.env|id_rsa|bash_history|config\.php/.test(joined)) return 4
  if (session.command_count || types.has('cowrie.command.input')) return 3
  if (session.login_success || types.has('cowrie.login.success')) return 3
  if (session.login_attempts || types.has('cowrie.login.failed')) return 2
  if (types.has('cowrie.session.connect')) return 1
  return 0
}


function phaseLabel(phase?: string) {
  const labels: Record<string, string> = {
    starting_services: 'Starting services',
    waiting_for_services: 'Checking services',
    running_attack: 'Attack running',
    processing_events: 'Processing events',
    waiting_for_action: 'Agent responding',
    generating_rules: 'Generating rules',
    completed: 'Complete',
    failed: 'Stopped',
  }
  return phase ? labels[phase] ?? phase : undefined
}

type GuidedStep = {
  id: string
  eyebrow: string
  title: string
  detail: string
  metric: (live: LiveResponse | null) => string
}

const guidedSteps: GuidedStep[] = [
  { id: 'setup', eyebrow: 'Step 1', title: 'Choose an attacker', detail: 'Select a standard attacker profile before the simulator connects to the decoy.', metric: (live) => live?.attack ? profileLabel(live.attack.profile) : 'Awaiting profile' },
  { id: 'services', eyebrow: 'Step 2', title: 'Prepare the environment', detail: 'ShadowMesh starts the local services and waits for Cowrie and Elasticsearch to become ready.', metric: (live) => phaseLabel(live?.attack?.phase) ?? 'Services ready' },
  { id: 'discovery', eyebrow: 'Step 3', title: 'SSH is discovered', detail: 'The attacker reaches the exposed SSH service and begins negotiating with the decoy.', metric: (live) => live?.events.some((event) => event.phase === 'discovery') ? 'Port 2222 reached' : 'Waiting for connection' },
  { id: 'credentials', eyebrow: 'Step 4', title: 'Credentials are tested', detail: 'Cowrie records each login attempt and makes the credential sequence visible.', metric: (live) => { const failed = (live?.events ?? []).filter((event) => event.event_type === 'cowrie.login.failed').length; const success = (live?.events ?? []).some((event) => event.event_type === 'cowrie.login.success'); return `${failed + (success ? 1 : 0)} attempt${failed + (success ? 1 : 0) === 1 ? '' : 's'}` } },
  { id: 'shell', eyebrow: 'Step 5', title: 'The fake shell opens', detail: 'The accepted credentials lead into Cowrie’s decoy shell, where post-login activity is captured.', metric: (live) => live?.session?.login_success || live?.events.some((event) => event.event_type === 'cowrie.login.success') ? 'Access granted' : 'Waiting for acceptance' },
  { id: 'bait', eyebrow: 'Step 6', title: 'Sensitive-path activity is observed', detail: 'Commands targeting credential-related paths are captured. They indicate attempted access, not exposure to a particular bait artifact.', metric: (live) => { const count = (live?.events ?? []).filter((event) => event.phase === 'bait').length; return count ? `${count} sensitive-path command${count === 1 ? '' : 's'}` : 'Waiting for sensitive-path activity' } },
  { id: 'response', eyebrow: 'Step 7', title: 'Baseline decision is recorded', detail: 'After the session closes, the deterministic baseline records an action that prepares deception for a future session.', metric: (live) => live?.actions.length ? `${live.actions.length} decision record${live.actions.length === 1 ? '' : 's'}` : 'Waiting for a decision record' },
  { id: 'rules', eyebrow: 'Step 8', title: 'Detection rules are recorded', detail: 'Observed behavior is converted into Snort and YARA output for later detection.', metric: (live) => live?.rules.length ? `${live.rules.length} rule record${live.rules.length === 1 ? '' : 's'}` : 'Preparing detection output' },
]

function guidedStepFor(live: LiveResponse | null) {
  if (!live?.attack) return 0
  if (live.rules.length || live.attack.phase === 'completed' || live.attack.phase === 'generating_rules') return 7
  if (live.actions.length || live.attack.phase === 'waiting_for_action') return 6
  if ((live.events ?? []).some((event) => event.phase === 'bait')) return 5
  if (live.session?.login_success || (live.events ?? []).some((event) => event.event_type === 'cowrie.login.success') || Boolean(live.session?.command_count)) return 4
  if ((live.events ?? []).some((event) => event.phase === 'credentials')) return 3
  if ((live.events ?? []).some((event) => event.phase === 'discovery')) return 2
  return 1
}


function eventHeadline(event?: Event) {
  if (!event) return 'Waiting for a command'
  if (event.command) return event.command
  const labels: Record<string, string> = {
    'cowrie.session.connect': 'SSH service identified',
    'cowrie.login.failed': 'Credential attempt rejected',
    'cowrie.login.success': 'Credentials accepted — shell opened',
    'cowrie.session.closed': 'Session closed',
    'cowrie.log.closed': 'Session recording closed',
  }
  return labels[event.event_type ?? ''] ?? event.event_type ?? 'Event recorded'
}

function App() {
  const [view, setView] = useState<View>('overview')
  const [services, setServices] = useState<ServicesResponse | null>(null)
  const [live, setLive] = useState<LiveResponse | null>(null)
  const [sessions, setSessions] = useState<Session[]>([])
  const [bait, setBait] = useState<BaitFile[]>([])
  const [rules, setRules] = useState<{ records: RuleRecord[]; files: RuleFile[] }>({ records: [], files: [] })
  const [jobs, setJobs] = useState<Job[]>([])
  const [profile, setProfile] = useState('opportunist')
  const [sessionCount, setSessionCount] = useState(1)
  const [profilePickerOpen, setProfilePickerOpen] = useState(false)
  const [guidedOpen, setGuidedOpen] = useState(false)
  const [guidedIndex, setGuidedIndex] = useState(0)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null)
  const [systemOpen, setSystemOpen] = useState(false)

  const refreshServices = useCallback(async () => {
    try { setServices(await api.get<ServicesResponse>('/api/services')) } catch { /* dashboard remains usable offline */ }
  }, [])
  const refreshLive = useCallback(async () => {
    try {
      const fresh = await api.get<LiveResponse>('/api/live')
      setLive((prev) => {
        if (!prev) return fresh
        if (!fresh) return prev

        // If scenario is the same, monotonically preserve events, actions, rules, and session
        const sameScenario =
          (fresh.attack?.job_id && prev.attack?.job_id && fresh.attack.job_id === prev.attack.job_id) ||
          (!fresh.attack?.job_id && !prev.attack?.job_id)

        if (sameScenario) {
          const mergedEvents =
            (fresh.events?.length ?? 0) >= (prev.events?.length ?? 0)
              ? fresh.events
              : prev.events
          const mergedActions =
            (fresh.actions?.length ?? 0) >= (prev.actions?.length ?? 0)
              ? fresh.actions
              : prev.actions
          const mergedRules =
            (fresh.rules?.length ?? 0) >= (prev.rules?.length ?? 0)
              ? fresh.rules
              : prev.rules
          const mergedSession = fresh.session ?? prev.session

          return {
            ...fresh,
            events: mergedEvents,
            actions: mergedActions,
            rules: mergedRules,
            session: mergedSession,
          }
        }

        return fresh
      })
    } catch {
      /* poll again without resetting state */
    }
  }, [])
  const refreshData = useCallback(async () => {
    try {
      const [sessionData, baitData, ruleData, jobData] = await Promise.all([
        api.get<{ sessions: Session[] }>('/api/sessions'),
        api.get<{ files: BaitFile[] }>('/api/bait'),
        api.get<{ records: RuleRecord[]; files: RuleFile[] }>('/api/rules'),
        api.get<{ jobs: Job[] }>('/api/jobs'),
      ])
      setSessions(sessionData.sessions)
      setBait(baitData.files)
      setRules(ruleData)
      setJobs(jobData.jobs)
    } catch { /* individual panels have their own empty states */ }
  }, [])

  useEffect(() => {
    void refreshServices(); void refreshLive(); void refreshData()
    const timer = window.setInterval(() => { void refreshLive() }, 900)
    const dataTimer = window.setInterval(() => { void refreshData() }, 2500)
    const serviceTimer = window.setInterval(() => { void refreshServices() }, 4000)
    return () => { window.clearInterval(timer); window.clearInterval(dataTimer); window.clearInterval(serviceTimer) }
  }, [refreshData, refreshLive, refreshServices])

  useEffect(() => {
    if (!systemOpen) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setSystemOpen(false) }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [systemOpen])

  useEffect(() => {
    if (!profilePickerOpen) return
    const selectedIndex = Math.max(0, attackerProfiles.findIndex((item) => item.id === profile))
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); setProfilePickerOpen(false); return }
      if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
        event.preventDefault(); setProfile(attackerProfiles[(selectedIndex + attackerProfiles.length - 1) % attackerProfiles.length].id)
      }
      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
        event.preventDefault(); setProfile(attackerProfiles[(selectedIndex + 1) % attackerProfiles.length].id)
      }
      if (event.key === 'Enter') { event.preventDefault(); void launchSelectedAttack() }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [profilePickerOpen, profile])

  useEffect(() => {
    if (!guidedOpen || !live?.attack) return
    setGuidedIndex((current) => Math.max(current, guidedStepFor(live)))
  }, [guidedOpen, live])

  useEffect(() => {
    if (!notice) return
    const timer = window.setTimeout(() => setNotice(null), 4500)
    return () => window.clearTimeout(timer)
  }, [notice])

  const runAction = async (path: string, body: Record<string, unknown>, success?: string) => {
    setBusy(true); setNotice(null)
    try {
      await api.post(path, body)
      if (success) setNotice({ type: 'success', message: success })
      await refreshServices(); await refreshData()
    }
    catch (error) { setNotice({ type: 'error', message: error instanceof Error ? error.message : 'Action failed' }) }
    finally { setBusy(false) }
  }

  const startAttack = async () => {
    setProfilePickerOpen(true)
  }
  const launchSelectedAttack = async () => {
    setProfilePickerOpen(false)
    setLive(null)
    setNotice(null)
    await runAction('/api/attack', { profile, sessions: sessionCount })
    await refreshLive()
  }
  const launchAttackDirect = async (overrideProfile?: string, isFollowUp?: boolean) => {
    const target = overrideProfile || profile
    if (overrideProfile && overrideProfile !== profile) {
      setProfile(overrideProfile)
    }
    setProfilePickerOpen(false)
    setLive(null)
    setNotice(null)
    await runAction('/api/attack', { profile: target, sessions: sessionCount, is_follow_up: Boolean(isFollowUp) })
    await refreshLive()
  }

  // Dynamic status banner reflecting authentic pipeline phase
  const scenarioBanner = useMemo(() => {
    if (!live?.attack) return null
    const { status, phase, profile: attProfile } = live.attack
    const pLabel = profileLabel(attProfile)
    if (status === 'running') {
      switch (phase) {
        case 'starting_services':
          return { type: 'info' as const, message: 'Starting local services…' }
        case 'waiting_for_services':
          return { type: 'info' as const, message: 'Waiting for Cowrie honeypot and Elasticsearch…' }
        case 'running_attack': {
          const hasAccepted = (live.events ?? []).some((e) => e.event_type === 'cowrie.login.success')
          if (hasAccepted) return { type: 'info' as const, message: `Shell access established (${pLabel}). Capturing interactive commands…` }
          const hasConn = (live.events ?? []).some((e) => e.event_type === 'cowrie.session.connect')
          if (hasConn) return { type: 'info' as const, message: `Attacker connected (${pLabel}). Testing credentials on port 2222…` }
          return { type: 'info' as const, message: `Intrusion in progress (${pLabel}). Decoy listening on port 2222…` }
        }
        case 'processing_events':
          return { type: 'info' as const, message: 'Session closed. Synthesizing behavioral telemetry…' }
        case 'waiting_for_action':
          return { type: 'info' as const, message: 'Session closed. Evaluating adaptive baseline decision…' }
        case 'generating_rules':
          return { type: 'info' as const, message: 'Decision recorded. Generating Snort and YARA intelligence…' }
        default:
          return { type: 'info' as const, message: `Intrusion in progress (${pLabel})…` }
      }
    }
    if (status === 'failed') {
      return { type: 'error' as const, message: live.attack.message ?? 'The scenario stopped unexpectedly.' }
    }
    return null
  }, [live])

  const [pointer, setPointer] = useState({ x: 50, y: 40 })
  useEffect(() => {
    let frameId: number
    const onMove = (e: PointerEvent) => {
      cancelAnimationFrame(frameId)
      frameId = requestAnimationFrame(() => {
        const x = Math.round((e.clientX / window.innerWidth) * 100)
        const y = Math.round((e.clientY / window.innerHeight) * 100)
        setPointer({ x, y })
      })
    }
    window.addEventListener('pointermove', onMove, { passive: true })
    return () => {
      window.removeEventListener('pointermove', onMove)
      cancelAnimationFrame(frameId)
    }
  }, [])

  const ambientState = useMemo(() => {
    if (!live?.attack) return 'idle'
    if (live.attack.status === 'running') {
      const hasAccepted = (live.events ?? []).some((e) => e.event_type === 'cowrie.login.success')
      const cmdCount = (live.events ?? []).filter((e) => e.event_type === 'cowrie.command.input').length
      if (hasAccepted && cmdCount === 0) return 'granted'
      if (cmdCount > 0) return 'observe'
      return 'running'
    }
    if (live.attack.status === 'completed') return 'complete'
    return 'idle'
  }, [live])

  const activeNotice = notice ?? scenarioBanner

  return (
    <>
      <div
        className={`ambient-background ambient-state-${ambientState}`}
        style={{
          '--pointer-x': `${pointer.x}%`,
          '--pointer-y': `${pointer.y}%`
        } as React.CSSProperties}
        aria-hidden="true"
      >
        <div className="ambient-glow glow-warm" />
        <div className="ambient-glow glow-cool" />
        <div className="ambient-glow glow-accent" />
        <div className="ambient-glow glow-pointer" />
        <div className="ambient-mesh-grid" />
      </div>
      <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><span /></div><div><strong>ShadowMesh</strong><small>Adaptive honeypot</small></div></div>
        <div className="side-section-label">Workspace</div>
        <nav className="nav-list" aria-label="Main navigation">
          {navItems.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${view === id ? 'selected' : ''}`} onClick={() => setView(id)}><Icon /><span>{label}</span>{id === 'overview' && live?.attack?.status === 'running' && <i className="nav-live-dot" />}</button>)}
        </nav>
        <div className="sidebar-spacer" />
        <div className="stack-summary"><div className="side-section-label">System</div><div className="stack-summary-title"><span className={`status-dot ${services?.online === services?.total && services?.total ? 'online' : ''}`} />{services ? `${services.online}/${services.total} services online` : 'Checking services'}</div><p>Live data is read from the local ShadowMesh stack.</p></div>
        <div className="sidebar-footer"><button className="quiet-button" onClick={() => { void refreshServices(); void refreshData() }}><RefreshIcon /> Refresh</button><a className="quiet-button" href="http://localhost:5601" target="_blank" rel="noreferrer"><ExternalIcon /> Kibana</a></div>
      </aside>
      <main className="main-content">
        <header className="topbar"><div><div className="eyebrow">ShadowMesh / {navItems.find((item) => item.id === view)?.label}</div><h1>{navItems.find((item) => item.id === view)?.label}</h1></div><div className="topbar-right"><span className="last-updated">Updated {relativeTime(live?.updated_at)}</span><span className="environment-pill"><span className={`status-dot ${services?.online ? 'online' : ''}`} />Local environment</span><button className={`icon-button ${systemOpen ? 'selected' : ''}`} aria-label="System controls" aria-expanded={systemOpen} onClick={() => setSystemOpen((value) => !value)}><SettingsIcon /></button></div></header>
        {activeNotice && <div className={`notice ${activeNotice.type}`}><span>{activeNotice.message}</span>{notice && <button onClick={() => setNotice(null)} aria-label="Dismiss"><CloseIcon /></button>}</div>}
        {view === 'overview' && (
          <Overview
            live={live}
            services={services}
            profile={profile}
            setProfile={setProfile}
            bait={bait}
            startAttack={startAttack}
            onRunIntrusion={launchAttackDirect}
            onRunFollowUp={() => launchAttackDirect(profile, true)}
            onGuidedReview={() => { setGuidedIndex(guidedStepFor(live)); setGuidedOpen(true) }}
            onInvestigate={() => { if (live?.session?.session_id) setSelectedSessionId(live.session.session_id); setView('sessions') }}
            busy={busy}
            onCancel={() => { void runAction('/api/attack/cancel', {}, 'The running scenario is being stopped.') }}
          />
        )}
        {view === 'sessions' && <Sessions sessions={sessions} selectedSessionId={selectedSessionId} onSelect={(id) => setSelectedSessionId(id)} />}
        {view === 'bait' && <Bait files={bait} onAction={runAction} busy={busy} />}
        {view === 'rules' && <Rules records={rules.records} files={rules.files} onAction={runAction} busy={busy} />}
      </main>
      {systemOpen && <SystemPanel services={services} jobs={jobs} busy={busy} onClose={() => setSystemOpen(false)} onAction={runAction} />}
      {profilePickerOpen && <ProfilePicker profile={profile} setProfile={setProfile} sessionCount={sessionCount} onClose={() => setProfilePickerOpen(false)} onLaunch={() => { void launchSelectedAttack() }} busy={busy} />}
      {guidedOpen && <GuidedReview live={live} index={guidedIndex} setIndex={setGuidedIndex} onClose={() => setGuidedOpen(false)} onStart={() => { setGuidedOpen(false); setProfilePickerOpen(true) }} />}
    </div>
    </>
  )
}

function ProfilePicker({ profile, setProfile, sessionCount, onClose, onLaunch, busy }: { profile: string; setProfile: (value: string) => void; sessionCount: number; onClose: () => void; onLaunch: () => void; busy: boolean }) {
  const selected = attackerProfiles.find((item) => item.id === profile) ?? attackerProfiles[1]
  const selectedIndex = attackerProfiles.findIndex((item) => item.id === selected.id)
  const selectedButton = useRef<HTMLButtonElement>(null)
  useEffect(() => { selectedButton.current?.focus() }, [selected.id])
  return <div className="profile-picker-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <section className="profile-picker" role="dialog" aria-modal="true" aria-labelledby="profile-picker-title">
      <div className="profile-picker-top"><div><span className="panel-kicker">Scenario setup</span><h2 id="profile-picker-title">Choose an attacker</h2><p>Select a profile to see how the intrusion will unfold.</p></div><button className="icon-button" onClick={onClose} aria-label="Close profile picker"><CloseIcon /></button></div>
      <div className="profile-picker-cards" role="radiogroup" aria-label="Attacker profiles">{attackerProfiles.map((item, index) => <button ref={item.id === selected.id ? selectedButton : undefined} key={item.id} className={`profile-card ${item.id === selected.id ? 'selected' : ''} ${index < selectedIndex ? 'before' : ''} ${index > selectedIndex ? 'after' : ''}`} role="radio" aria-checked={item.id === selected.id} onClick={() => setProfile(item.id)}><span className="profile-card-index">{item.index}</span><span className="profile-card-body"><strong>{item.label}</strong><span>{item.summary}</span><small>{item.signal}</small></span><span className="profile-card-mark" aria-hidden="true">{item.id === selected.id ? 'Selected' : 'Choose'}</span></button>)}</div>
      <div className="profile-picker-progress" aria-live="polite"><span>{String(selectedIndex + 1).padStart(2, '0')} / {String(attackerProfiles.length).padStart(2, '0')}</span><div>{attackerProfiles.map((item) => <i key={item.id} className={item.id === selected.id ? 'active' : ''} />)}</div><span>{selected.signal}</span></div>
      <div className="profile-picker-detail"><div><span className="panel-kicker">Selected profile</span><strong>{selected.label}</strong><p>{selected.detail}</p><small>{selected.credentialPlan}</small></div><div className="profile-picker-meta"><span>Sessions</span><strong>{sessionCount}</strong></div></div>
      <div className="profile-picker-footer"><span className="key-hint"><kbd>←</kbd><kbd>→</kbd> choose <kbd>Enter</kbd> launch <kbd>Esc</kbd> close</span><button className="primary-button" disabled={busy} onClick={onLaunch}><PlayIcon />Start scenario<ArrowIcon /></button></div>
    </section>
  </div>
}

function SystemPanel({ services, jobs, busy, onClose, onAction }: { services: ServicesResponse | null; jobs: Job[]; busy: boolean; onClose: () => void; onAction: (path: string, body: Record<string, unknown>, success: string) => Promise<void> }) {
  return <><button className="drawer-backdrop" aria-label="Close system controls" onClick={onClose} /><aside className="system-drawer" aria-label="System controls"><div className="drawer-header"><div><span className="panel-kicker">Local environment</span><h2>System</h2></div><button className="icon-button" onClick={onClose} aria-label="Close"><CloseIcon /></button></div><div className="drawer-actions"><button className="primary-button" disabled={busy} onClick={() => onAction('/api/stack/start', {}, 'Services are starting in the background.')}>Start services</button><button className="secondary-button danger-button" disabled={busy} onClick={() => onAction('/api/stack/stop', {}, 'Services are stopping in the background.')}>Stop services</button></div><section className="drawer-section"><div className="drawer-section-head"><strong>Services</strong><span>{services ? `${services.online}/${services.total} online` : 'Checking'}</span></div><div className="drawer-service-list">{services?.services.map((service) => <div className="drawer-service" key={service.id}><span className={`status-dot ${service.online ? 'online' : ''}`} /><div><strong>{service.name}</strong><small>{service.state}</small></div></div>) ?? <Empty text="Checking local services…" />}</div></section><section className="drawer-section"><div className="drawer-section-head"><strong>Recent jobs</strong><span>{jobs.length}</span></div><div className="job-list">{jobs.length ? jobs.slice(0, 6).map((job) => <div className="job-item" key={job.id}><span className={`job-state ${job.status}`} /><div><strong>{job.name}</strong><small>{job.status} · {relativeTime(job.finished_at ?? job.started_at)}</small></div></div>) : <Empty text="No dashboard jobs have run yet." />}</div></section><div className="drawer-links"><a href="http://localhost:5601" target="_blank" rel="noreferrer">Open Kibana <ExternalIcon /></a><a href="http://localhost:9200" target="_blank" rel="noreferrer">Open Elasticsearch <ExternalIcon /></a></div></aside></>
}

function Overview({
  live,
  services,
  profile,
  setProfile,
  bait,
  busy,
  startAttack,
  onRunIntrusion,
  onRunFollowUp,
  onGuidedReview,
  onInvestigate,
  onCancel,
}: {
  live: LiveResponse | null
  services: ServicesResponse | null
  profile: string
  setProfile: (profile: string) => void
  bait: BaitFile[]
  busy: boolean
  startAttack: () => void
  onRunIntrusion: (profile?: string) => Promise<void>
  onRunFollowUp?: () => Promise<void>
  onGuidedReview: () => void
  onInvestigate: () => void
  onCancel: () => void
}) {
  return (
    <CommandCenter
      live={live}
      services={services?.services ?? []}
      profile={profile}
      setProfile={setProfile}
      onRunIntrusion={onRunIntrusion}
      onRunFollowUp={onRunFollowUp}
      bait={bait}
      busy={busy}
      onChooseAttacker={startAttack}
      onGuidedReview={onGuidedReview}
      onInvestigate={onInvestigate}
      onCancel={onCancel}
    />
  )
}

function GuidedReview({ live, index, setIndex, onClose, onStart }: { live: LiveResponse | null; index: number; setIndex: (value: number) => void; onClose: () => void; onStart: () => void }) {
  const step = guidedSteps[Math.max(0, Math.min(guidedSteps.length - 1, index))]
  const completed = guidedStepFor(live)
  const failed = live?.attack?.status === 'failed'
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); onClose() }
      if (event.key === 'ArrowLeft') { event.preventDefault(); setIndex(Math.max(0, index - 1)) }
      if (event.key === 'ArrowRight' || event.key === 'Enter') { event.preventDefault(); setIndex(Math.min(guidedSteps.length - 1, index + 1)) }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [index, onClose, setIndex])
  return <div className="guided-backdrop" role="presentation"><section className={`guided-review ${failed ? 'failed' : ''}`} role="dialog" aria-modal="true" aria-labelledby="guided-title"><header className="guided-header"><div><span className="panel-kicker">Guided review</span><h2 id="guided-title">{failed ? 'Scenario needs attention' : 'Follow the intrusion'}</h2><p>{failed ? live?.attack?.message ?? 'The scenario stopped before the full story was recorded.' : 'ShadowMesh connects each independent service into one reviewable story.'}</p></div><button className="icon-button" onClick={onClose} aria-label="Exit guided review"><CloseIcon /></button></header><div className="guided-progress">{guidedSteps.map((item, itemIndex) => <button key={item.id} className={`${itemIndex === index ? 'active' : ''} ${itemIndex <= completed ? 'complete' : ''}`} onClick={() => setIndex(itemIndex)} aria-label={`Go to ${item.title}`}><span>{itemIndex + 1}</span><i /></button>)}</div><div className="guided-content"><span className="guided-eyebrow">{failed ? 'Recovery' : step.eyebrow}</span><h3>{failed ? 'Review the captured evidence' : step.title}</h3><p>{failed ? 'You can close this guide, inspect the captured session, and restart after the local service issue is resolved.' : step.detail}</p><div className="guided-metric"><span>{failed ? 'Run status' : 'Live signal'}</span><strong>{failed ? 'Stopped' : step.metric(live)}</strong></div></div><footer className="guided-footer"><span><kbd>←</kbd><kbd>→</kbd> navigate <kbd>Esc</kbd> exit</span><div>{!live?.attack && <button className="secondary-button" onClick={onStart}>Choose attacker</button>}<button className="secondary-button" disabled={index === 0} onClick={() => setIndex(index - 1)}>Previous</button><button className="primary-button" onClick={() => setIndex(Math.min(guidedSteps.length - 1, index + 1))}>{index === guidedSteps.length - 1 ? 'Stay on rules' : 'Next step'}<ArrowIcon /></button></div></footer></section></div>
}

function Empty({ text }: { text: string }) { return <div className="empty-state"><span /><p>{text}</p></div> }

function Sessions({ sessions, selectedSessionId, onSelect }: { sessions: Session[]; selectedSessionId: string | null; onSelect: (id: string) => void }) {
  const selected = sessions.find((session) => session.session_id === selectedSessionId) ?? null
  return <div className="page-view"><div className="page-heading"><div><p className="intro-kicker">Captured activity</p><h2>Sessions</h2><p>Every simulated connection, summarized in plain language.</p></div><span className="count-label">{sessions.length} sessions</span></div><div className="table-panel"><div className="table-head"><span>Profile</span><span>Session</span><span>Activity</span><span>Outcome</span><span>Time</span><span /></div>{sessions.length ? sessions.map((session) => <button className={`table-row ${selectedSessionId === session.session_id ? 'selected' : ''}`} key={session.session_id} onClick={() => session.session_id && onSelect(session.session_id)}><span><b className="type-dot" />{profileLabel(session.attacker_profile)}</span><span className="mono">{session.session_id?.slice(0, 18) ?? '—'}</span><span>{session.attack_type ?? 'SSH activity'} · {session.command_count ?? 0} commands</span><span><span className={`state-badge ${session.session_active ? 'active' : ''}`}>{session.session_active ? 'Active' : 'Closed'}</span></span><span>{formatTime(session['@timestamp'] ?? session.session_end)}</span><ChevronIcon /></button>) : <Empty text="No sessions have been recorded yet." />}</div>{selected && <SessionDetail session={selected} />}</div>
}

function SessionDetail({ session }: { session: Session }) {
  const [events, setEvents] = useState<Event[]>([])
  const [actions, setActions] = useState<Action[]>([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    if (!session.session_id) return
    setLoading(true)
    void Promise.all([
      api.get<{ events: Event[] }>(`/api/sessions/${encodeURIComponent(session.session_id)}/events`),
      api.get<{ actions: Action[] }>(`/api/sessions/${encodeURIComponent(session.session_id)}/actions`),
    ]).then(([eventData, actionData]) => { setEvents(eventData.events); setActions(actionData.actions) }).catch(() => { setEvents([]); setActions([]) }).finally(() => setLoading(false))
  }, [session.session_id])
  return <section className="session-detail"><div className="detail-heading"><div><span className="panel-kicker">Session timeline</span><h3>{session.attack_type ?? 'SSH activity'}</h3>{session.attacker_profile && <span className="profile-badge">{profileLabel(session.attacker_profile)} profile</span>}<p>{session.explanation}</p></div><span className="mono">{session.session_id}</span></div><div className="detail-grid"><div className="timeline-panel"><div className="timeline-head"><strong>Observed activity</strong><span>{loading ? 'Loading' : `${events.length} events`}</span></div>{loading ? <Empty text="Loading the session timeline…" /> : events.length ? <div className="timeline">{events.map((event, index) => <div className="timeline-item" key={`${event['@timestamp'] ?? index}-${index}`}><span className={`timeline-marker ${event.phase ?? ''}`} /><div><div className="timeline-meta">{formatTime(event['@timestamp'] ?? event.timestamp)} · {event.phase ?? 'connection'}</div><strong>{eventHeadline(event)}</strong><p>{event.explanation}</p></div></div>)}</div> : <Empty text="No normalized events are available for this session." />}</div><div className="detail-side"><div className="detail-stat"><span>Attacker</span><strong>{session.attacker_ip ?? '—'}</strong></div><div className="detail-stat"><span>Commands</span><strong>{session.command_count ?? 0}</strong></div><div className="detail-stat"><span>ATT&CK signals</span><strong>{session.ttp_count ?? 0}</strong></div><div className="detail-actions"><div className="timeline-head"><strong>Adaptive actions</strong><span>{actions.length}</span></div>{actions.length ? actions.map((action, index) => <div className="action-item" key={`${action['@timestamp'] ?? index}-${index}`}><ShieldIcon /><div><strong>{action.name || action.action_name || 'Decision'}</strong><p>{action.explanation}</p></div></div>) : <Empty text="No adaptive action was emitted." />}</div></div></div></section>
}

function Bait({ files, onAction, busy }: { files: BaitFile[]; onAction: (path: string, body: Record<string, unknown>, success: string) => Promise<void>; busy: boolean }) {
  const [selected, setSelected] = useState<BaitFile | null>(files[0] ?? null)
  useEffect(() => { if (!selected || !files.some((file) => file.id === selected.id)) setSelected(files[0] ?? null) }, [files, selected])
  return <div className="page-view"><div className="page-heading"><div><p className="intro-kicker">Generated deception</p><h2>Bait</h2><p>Files the attacker can discover inside the Cowrie filesystem.</p></div><button className="secondary-button" disabled={busy} onClick={() => onAction('/api/bait/regenerate', {}, 'Bait generation started.')}>Regenerate bait <RefreshIcon /></button></div><div className="bait-layout"><div className="file-list">{files.map((file) => <button className={`file-item ${selected?.id === file.id ? 'selected' : ''}`} onClick={() => setSelected(file)} key={file.id}><BaitIcon /><span><strong>{file.name}</strong><small>{file.attacker_path}</small></span><span className={`file-state ${file.exists ? 'ready' : ''}`}>{file.exists ? 'Ready' : 'Missing'}</span></button>)}</div><BaitPreview file={selected} /></div></div>
}

function BaitPreview({ file }: { file: BaitFile | null }) {
  const [content, setContent] = useState('')
  useEffect(() => { if (!file) return; void api.get<{ content: string }>(`/api/bait/${encodeURIComponent(file.id)}`).then((data) => setContent(data.content)).catch(() => setContent('')) }, [file])
  if (!file) return <div className="preview-panel"><Empty text="Choose a bait file to inspect it." /></div>
  return <div className="preview-panel"><div className="preview-header"><div><span className="panel-kicker">Attacker-visible path</span><h3>{file.attacker_path}</h3><p>{file.explanation}</p></div><span className={`state-badge ${file.exists ? 'active' : ''}`}>{file.exists ? `${file.size.toLocaleString()} bytes` : 'Not generated'}</span></div><pre>{content || 'No preview available.'}</pre></div>
}

function Rules({ records, files, onAction, busy }: { records: RuleRecord[]; files: RuleFile[]; onAction: (path: string, body: Record<string, unknown>, success: string) => Promise<void>; busy: boolean }) {
  const [selected, setSelected] = useState<RuleFile | null>(files[0] ?? null)
  const [content, setContent] = useState('')
  useEffect(() => { if (!selected || !files.some((file) => file.id === selected.id)) setSelected(files[0] ?? null) }, [files, selected])
  useEffect(() => { if (!selected) return; void api.get<{ content: string }>(`/api/rule-files/${encodeURIComponent(selected.id)}`).then((data) => setContent(data.content)).catch(() => setContent('')) }, [selected])
  return <div className="page-view"><div className="page-heading"><div><p className="intro-kicker">Detection output</p><h2>Rules</h2><p>Generated Snort and YARA artifacts linked back to observed sessions.</p></div><button className="primary-button compact" disabled={busy} onClick={() => onAction('/api/rules/generate', {}, 'Rule generation started.')}>Generate rules <ArrowIcon /></button></div><div className="rules-summary"><div><span>Rule records</span><strong>{records.length}</strong></div><div><span>Files on disk</span><strong>{files.length}</strong></div><div><span>Latest output</span><strong>{files[0]?.modified_at ? formatTime(files[0].modified_at) : '—'}</strong></div></div><div className="rules-layout"><div className="file-list">{files.length ? files.map((file) => <button className={`file-item ${selected?.id === file.id ? 'selected' : ''}`} onClick={() => setSelected(file)} key={file.id}><RulesIcon /><span><strong>{file.name}</strong><small>{file.type} · {file.size.toLocaleString()} bytes</small></span><ChevronIcon /></button>) : <Empty text="No rule files have been generated yet." />}</div><div className="preview-panel"><div className="preview-header"><div><span className="panel-kicker">Rule preview</span><h3>{selected?.name ?? 'No file selected'}</h3></div></div><pre>{content || 'Generate rules after a session to see the output here.'}</pre></div></div></div>
}

export default App
