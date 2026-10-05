import { useMemo, useState, useEffect, useRef } from 'react'
import type { Action, BaitFile, Event, LiveResponse, RuleRecord, Service, AttackerProfile } from './types'
import { ATTACKER_PROFILES } from './types'
import { ArrowIcon, BaitIcon, ChevronIcon, PlayIcon, RulesIcon, ShieldIcon, TerminalIcon } from './icons'
import { api } from './api'

/* ═══════════════════════════════════════════════════
   Types & Constants
   ═══════════════════════════════════════════════════ */

export type Stage = 'attack' | 'observe' | 'understand' | 'decide' | 'deceive' | 'detect' | 'learn'

export const STAGES: Stage[] = ['attack', 'observe', 'understand', 'decide', 'deceive', 'detect', 'learn']

const STAGE_LABELS: Record<Stage, string> = {
  attack: 'Attack',
  observe: 'Observe',
  understand: 'Understand',
  decide: 'Decide',
  deceive: 'Deceive',
  detect: 'Detect',
  learn: 'Learn',
}

const STAGE_KICKERS: Record<Stage, string> = {
  attack: 'Chapter 01 · Initial Access',
  observe: 'Chapter 02 · Post-Access Telemetry',
  understand: 'Chapter 03 · Behavioral Synthesis',
  decide: 'Chapter 04 · Adaptive Decision',
  deceive: 'Chapter 05 · Deception Environment',
  detect: 'Chapter 06 · Threat Detection',
  learn: 'Chapter 07 · System Learning',
}

/* ═══════════════════════════════════════════════════
   Canonical Metrics & Helpers
   ═══════════════════════════════════════════════════ */

export function deriveCanonicalMetrics(live: LiveResponse | null) {
  const events = live?.events ?? []
  const session = live?.session
  const actions = live?.actions ?? []
  const rules = live?.rules ?? []

  const connection = events.find(e => e.event_type === 'cowrie.session.connect')
  const authEvents = events.filter(e => e.event_type === 'cowrie.login.failed' || e.event_type === 'cowrie.login.success')
  const failedAuthEvents = authEvents.filter(e => e.event_type === 'cowrie.login.failed')
  const acceptedAuthEvent = authEvents.find(e => e.event_type === 'cowrie.login.success')

  // Canonical attempt counts:
  // Derived strictly from auth events if present; otherwise harmonized from session summary
  const failedLogins = authEvents.length > 0
    ? failedAuthEvents.length
    : (session?.login_success ? Math.max(0, (session?.login_attempts ?? 0) - 1) : (session?.login_attempts ?? 0))
  const acceptedLogins = authEvents.length > 0
    ? (acceptedAuthEvent ? 1 : 0)
    : (session?.login_success ? 1 : 0)
  const totalLogins = failedLogins + acceptedLogins

  const commandEvents = events.filter(e => e.event_type === 'cowrie.command.input')
  const commandCount = commandEvents.length > 0
    ? commandEvents.length
    : (session?.command_count ?? session?.commands?.length ?? 0)

  const sensitiveEvents = commandEvents.filter(e =>
    e.phase === 'bait' || /\/etc\/(passwd|shadow)|\.env|id_rsa/.test(e.command ?? '')
  )
  const sensitiveCount = sensitiveEvents.length

  const followUpEvents = commandEvents.filter(e =>
    (e.command ?? '').includes('grep') && /backupsvc|cloudsync/.test(e.command ?? '')
  )
  const hasFollowUp = followUpEvents.length > 0
  const adaptiveFollowUpCmd = followUpEvents[0]

  const durationSec = session?.session_duration
    ? Math.round(session.session_duration)
    : (session?.session_start && session?.session_end
        ? Math.round((new Date(session.session_end).getTime() - new Date(session.session_start).getTime()) / 1000)
        : null)

  const totalRules = rules.reduce((acc, r) => acc + Number(r.rule_count ?? 0), 0)
  const snortRuleCount = rules.reduce((acc, r) => acc + (r.snort_rules?.length ?? 0), 0)
  const yaraRuleCount = rules.reduce((acc, r) => acc + (r.yara_rules?.length ?? 0), 0)

  return {
    connection,
    authEvents,
    failedAuthEvents,
    acceptedAuthEvent,
    hasSuccess: Boolean(acceptedAuthEvent || session?.login_success),
    failedLogins,
    acceptedLogins,
    totalLogins,
    commandEvents,
    commandCount,
    sensitiveEvents,
    sensitiveCount,
    followUpEvents,
    hasFollowUp,
    adaptiveFollowUpCmd,
    durationSec,
    totalRules,
    snortRuleCount,
    yaraRuleCount,
    actions,
    latestAction: actions.at(-1),
    rules,
    latestRule: rules.at(-1),
  }
}

export function deriveActiveStageFromBackend(
  live: LiveResponse | null,
  metrics: ReturnType<typeof deriveCanonicalMetrics>
): {
  stage: Stage
  isCompleted: boolean
  isRunning: boolean
  isIdle: boolean
} {
  const status = live?.attack?.status
  const phase = live?.attack?.phase
  const isRunning = status === 'running'
  const isCompleted = status === 'completed' || phase === 'completed'
  const hasAuth = metrics.authEvents.length > 0 || Boolean(metrics.connection)
  const hasCommands = metrics.commandCount > 0
  const hasActions = (live?.actions?.length ?? 0) > 0
  const hasRules = metrics.totalRules > 0
  const isIdle = !live?.attack && !hasAuth && !hasCommands && !hasActions && !hasRules

  if (isIdle) {
    return { stage: 'attack', isCompleted: false, isRunning: false, isIdle: true }
  }

  const isFailed = status === 'failed' || phase === 'failed'

  if (isCompleted && !isFailed) {
    return { stage: 'learn', isCompleted: true, isRunning: false, isIdle: false }
  }

  // If stopped or failed, terminal stage is the furthest stage with evidence:
  if (isFailed) {
    let termStage: Stage = 'attack'
    if (hasRules) termStage = 'detect'
    else if (hasActions) termStage = 'deceive'
    else if (hasCommands) termStage = 'observe'
    return { stage: termStage, isCompleted: true, isRunning: false, isIdle: false }
  }

  // Active running scenario progression strictly based on real evidence and phase:
  if (phase === 'generating_rules' || (hasRules && phase !== 'materializing_bait' && phase !== 'waiting_for_action')) {
    return { stage: 'detect', isCompleted: false, isRunning, isIdle: false }
  }
  if (phase === 'materializing_bait' || (hasActions && !hasRules && phase !== 'waiting_for_action')) {
    return { stage: 'deceive', isCompleted: false, isRunning, isIdle: false }
  }
  if (phase === 'waiting_for_action' || hasActions) {
    return { stage: 'decide', isCompleted: false, isRunning, isIdle: false }
  }
  const isSessionClosed =
    live?.session?.session_active === false ||
    live?.events?.some(e => e.event_type === 'cowrie.session.closed') ||
    phase === 'processing_events'
  if (isSessionClosed && hasCommands) {
    return { stage: 'understand', isCompleted: false, isRunning, isIdle: false }
  }
  if (hasCommands) {
    return { stage: 'observe', isCompleted: false, isRunning, isIdle: false }
  }

  return { stage: 'attack', isCompleted: false, isRunning, isIdle: false }
}

function fmtTime(v?: string) {
  if (!v) return ''
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function profileName(p?: string) {
  return { scriptkiddie: 'Script Kiddie', opportunist: 'Opportunist', targeted: 'Targeted' }[p ?? ''] ?? p ?? 'Unknown Profile'
}

function profileDesc(p?: string) {
  switch (p) {
    case 'scriptkiddie':
      return 'Fast scanner testing 4 common credentials, then running 5 basic host reconnaissance commands.'
    case 'opportunist':
      return 'Probes 5 credentials, enters shell, runs 11 commands, and tests follow-ups on discovered bait.'
    case 'targeted':
      return 'Deliberate probe testing 3 credentials, persistence, cron jobs, and 19 deep system discovery commands.'
    default:
      return 'Automated SSH intrusion pattern.'
  }
}

export function deriveTacticalPhase(commandEvents: Event[]): {
  phaseName: string
  phaseNumber: string
  phaseDescription: string
  isSensitive: boolean
  isFollowUp: boolean
} {
  if (commandEvents.length === 0) {
    return {
      phaseName: 'Initial Decoy Shell',
      phaseNumber: '00',
      phaseDescription: 'Interactive shell allocated. Decoy listening for attacker commands.',
      isSensitive: false,
      isFollowUp: false,
    }
  }
  const latest = commandEvents[commandEvents.length - 1]?.command ?? ''
  if (latest.includes('grep') && /backupsvc|cloudsync/.test(latest)) {
    return {
      phaseName: 'Bait Investigation',
      phaseNumber: '05',
      phaseDescription: 'The attacker detected the staged bait marker in /etc/passwd and initiated targeted inspection.',
      isSensitive: false,
      isFollowUp: true,
    }
  }
  if (/wget|curl|chmod|\/tmp\//.test(latest)) {
    return {
      phaseName: 'Payload Staging',
      phaseNumber: '04',
      phaseDescription: 'The attacker is staging remote utilities and preparing executable artifacts.',
      isSensitive: false,
      isFollowUp: false,
    }
  }
  if (/\/etc\/(passwd|shadow)|\.env|id_rsa/.test(latest)) {
    return {
      phaseName: 'Credential Probing',
      phaseNumber: '03',
      phaseDescription: 'The attacker is querying credential files and sensitive system accounts.',
      isSensitive: true,
      isFollowUp: false,
    }
  }
  if (/uname|whoami|id|pwd|hostname/.test(latest)) {
    return {
      phaseName: 'Identity & Environment',
      phaseNumber: '01',
      phaseDescription: 'The attacker is confirming shell privileges and basic operating system details.',
      isSensitive: false,
      isFollowUp: false,
    }
  }
  return {
    phaseName: 'System Discovery',
    phaseNumber: '02',
    phaseDescription: 'The attacker is exploring filesystem mounts, configuration files, and running processes.',
    isSensitive: false,
    isFollowUp: false,
  }
}

function scopeText(action?: Action) {
  const s = action?.parameters?.activation_scope
  if (s === 'next_session') return 'Prepared for next session'
  if (s === 'live_session') return 'Live session scope'
  return action ? 'Scope not reported' : '—'
}

export function TwoSessionCard({
  live,
  metrics,
}: {
  live: LiveResponse | null
  metrics: ReturnType<typeof deriveCanonicalMetrics>
}) {
  const prev = live?.previous_run
  const currentSessionId = live?.session?.session_id
  const isFollowUpRun = Boolean(live?.attack?.is_follow_up)
  const isDifferentSession = Boolean(prev?.session_id && currentSessionId && prev.session_id !== currentSessionId)
  const hasFollowUpSession = isFollowUpRun || isDifferentSession
  const followUpHappened = metrics.hasFollowUp || Boolean(prev?.follow_up_occurred && hasFollowUpSession)

  if (!prev && !currentSessionId) return null

  const probeSessionId = (hasFollowUpSession && prev?.session_id) ? prev.session_id : (currentSessionId ?? prev?.session_id ?? '')
  const probeProfile = (hasFollowUpSession && prev?.profile) ? prev.profile : (live?.attack?.profile ?? prev?.profile)
  const probeAction = (hasFollowUpSession && prev?.action) ? prev.action : (metrics.latestAction ?? prev?.action)

  return (
    <div className="two-session-card">
      <div className="two-session-header">
        <div>
          <span className="session-col-eyebrow">Continuous Intrusion Narrative</span>
          <h4>Two-Session Adaptive Deception Lifecycle</h4>
        </div>
        <span className="two-session-badge">
          {hasFollowUpSession ? 'Multi-Session Deception Active' : 'Session History Tracked'}
        </span>
      </div>

      <div className="two-session-grid">
        {/* Session 1: Initial Probe */}
        <div className="session-col">
          <span className="session-col-eyebrow">Session 01 · Initial Probe</span>
          <strong className="session-col-title">{profileName(probeProfile)} Intrusion</strong>
          <div className="session-col-details">
            <div><span>Session ID:</span> <code>{probeSessionId ? probeSessionId.slice(0, 14) : '—'}</code></div>
            <div><span>Observed Action:</span> Attacker queried <code>/etc/passwd</code></div>
            <div><span>HoneyFS State:</span> Default unseeded decoy</div>
            <div><span>Follow-up Queries:</span> <strong>0</strong> (no bait marker present)</div>
            <div><span>Adaptive Decision:</span> <code>{probeAction?.name ?? 'show_fake_credentials'}</code></div>
            <div><span>Prepared Scope:</span> <strong>Next session</strong></div>
          </div>
          <div className="session-col-outcome outcome-unseeded">
            Outcome: Baseline policy recorded decision and prepared synthetic accounts for next session.
          </div>
        </div>

        {/* Session 2: Prepared Environment */}
        <div className="session-col col-primed">
          <span className="session-col-eyebrow">Session 02 · Prepared Environment</span>
          <strong className="session-col-title">
            {hasFollowUpSession ? `${profileName(live?.attack?.profile || 'Follow-up')} Intrusion` : 'Awaiting Follow-up Intrusion'}
          </strong>
          <div className="session-col-details">
            <div><span>Session ID:</span> <code>{hasFollowUpSession ? (currentSessionId?.slice(0, 14) ?? 'In Progress') : 'Pending Launch'}</code></div>
            <div><span>HoneyFS State:</span> <strong>Synthetic accounts mounted</strong> (<code>backupsvc</code>, <code>cloudsync</code>)</div>
            <div><span>Attacker Behavior:</span> {hasFollowUpSession ? 'Re-probed /etc/passwd and observed synthetic decoy entries' : 'Awaiting follow-up intruder to probe staged decoy'}</div>
            <div>
              <span>Real Follow-up Query:</span>{' '}
              {hasFollowUpSession && metrics.adaptiveFollowUpCmd ? (
                <code>{metrics.adaptiveFollowUpCmd.command}</code>
              ) : hasFollowUpSession && metrics.hasFollowUp ? (
                <code>Bait query captured</code>
              ) : (
                <code>Awaiting command...</code>
              )}
            </div>
          </div>
          <div className={`session-col-outcome ${followUpHappened ? 'outcome-payoff' : 'outcome-unseeded'}`}>
            {followUpHappened ? (
              <span>✓ Prepared bait was queried by the follow-up intruder</span>
            ) : hasFollowUpSession ? (
              <span>Decoy environment prepared; awaiting intruder queries...</span>
            ) : (
              <span>Decoy environment prepared. Click &quot;Run Follow-up Intrusion&quot; above to test bait engagement.</span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function stageSummary(id: Stage, metrics: ReturnType<typeof deriveCanonicalMetrics>, session?: LiveResponse['session']): string {
  switch (id) {
    case 'attack': {
      if (metrics.acceptedLogins > 0) return `${metrics.failedLogins} rejected · 01 accepted`
      if (metrics.failedLogins > 0) return `${metrics.failedLogins} rejected`
      if (metrics.connection) return 'Connected'
      return 'Ready'
    }
    case 'observe': {
      return metrics.commandCount ? `${metrics.commandCount} commands` : 'Decoy shell'
    }
    case 'understand': {
      return session?.attack_type ? session.attack_type.replace(/ \+ /g, ', ') : 'Synthesis'
    }
    case 'decide': {
      return metrics.latestAction?.name?.replaceAll('_', ' ') ?? 'Baseline'
    }
    case 'deceive': {
      return metrics.latestAction?.parameters?.activation_scope === 'next_session' ? 'Next session' : 'Bait cache'
    }
    case 'detect': {
      return metrics.totalRules ? `${metrics.totalRules} rules` : 'Intelligence'
    }
    case 'learn':
      return 'Offline'
  }
}

/* ═══════════════════════════════════════════════════
   Main CommandCenter Component
   ═══════════════════════════════════════════════════ */

export function CommandCenter({
  live,
  services,
  profile,
  setProfile,
  onRunIntrusion,
  onRunFollowUp,
  bait,
  busy,
  onChooseAttacker,
  onGuidedReview,
  onInvestigate,
  onCancel,
}: {
  live: LiveResponse | null
  services: Service[]
  profile: string
  setProfile?: (p: string) => void
  onRunIntrusion?: (p?: string) => Promise<void>
  onRunFollowUp?: () => Promise<void>
  bait: BaitFile[]
  busy: boolean
  onChooseAttacker: () => void
  onGuidedReview: () => void
  onInvestigate: () => void
  onCancel?: () => void
}) {
  const metrics = useMemo(() => deriveCanonicalMetrics(live), [live])
  const backendDerived = useMemo(() => deriveActiveStageFromBackend(live, metrics), [live, metrics])

  const events = live?.events ?? []
  const running = live?.attack?.status === 'running'
  const failed = live?.attack?.status === 'failed'
  const completed = live?.attack?.status === 'completed' || live?.attack?.phase === 'completed'
  const currentJobId = live?.attack?.job_id ?? null

  const hasEvidence = Boolean(
    live?.session?.session_id ||
    events.length > 0 ||
    (live?.actions?.length ?? 0) > 0 ||
    (live?.rules?.length ?? 0) > 0
  )

  const highestLiveStageIndexRef = useRef<number>(0)
  const lastJobIdRef = useRef<string | null>(null)
  const initializedRef = useRef<boolean>(false)

  // Stage & Mode state initialized from authentic backend evidence:
  const [currentStage, setCurrentStage] = useState<Stage>(() => backendDerived.stage)
  const [mode, setMode] = useState<'live' | 'review'>(() => (backendDerived.isCompleted ? 'review' : 'live'))
  const [evidenceOpen, setEvidenceOpen] = useState(false)

  // Initial synchronization upon first data arrival / hydration:
  useEffect(() => {
    if (!initializedRef.current && live) {
      initializedRef.current = true
      lastJobIdRef.current = currentJobId
      const targetStage = backendDerived.stage
      setCurrentStage(targetStage)
      highestLiveStageIndexRef.current = STAGES.indexOf(targetStage)
      setMode(backendDerived.isCompleted ? 'review' : 'live')
    }
  }, [live, backendDerived, currentJobId])

  // When a brand new attack scenario begins (job_id changed):
  useEffect(() => {
    if (currentJobId && lastJobIdRef.current && currentJobId !== lastJobIdRef.current) {
      lastJobIdRef.current = currentJobId
      highestLiveStageIndexRef.current = 0
      setCurrentStage('attack')
      setMode('live')
      setEvidenceOpen(false)
    } else if (currentJobId && !lastJobIdRef.current) {
      lastJobIdRef.current = currentJobId
    }
  }, [currentJobId])

  // Monotonic Live Progression:
  // When running in live mode, ensure the stage monotonically advances as real events arrive
  useEffect(() => {
    if (mode !== 'live' || !running) return

    const derivedIdx = STAGES.indexOf(backendDerived.stage)

    // Special story beat: if on 'attack' and access is granted (login.success),
    // give ACCESS GRANTED a brief visual beat (~1.8s) before advancing to 'observe'
    // UNLESS commands have already arrived (in which case derivedIdx is already >= 1).
    if (currentStage === 'attack' && metrics.hasSuccess && metrics.commandCount === 0) {
      const timer = window.setTimeout(() => {
        if (mode === 'live' && running) {
          highestLiveStageIndexRef.current = Math.max(highestLiveStageIndexRef.current, 1)
          setCurrentStage('observe')
        }
      }, 1800)
      return () => window.clearTimeout(timer)
    }

    // Otherwise advance strictly monotonically based on evidence:
    if (derivedIdx > highestLiveStageIndexRef.current) {
      highestLiveStageIndexRef.current = derivedIdx
      setCurrentStage(backendDerived.stage)
    }
  }, [mode, running, backendDerived, currentStage, metrics.hasSuccess, metrics.commandCount])

  // Transition to completed while in live mode:
  useEffect(() => {
    if (completed && !running && mode === 'live') {
      const timer = window.setTimeout(() => {
        highestLiveStageIndexRef.current = STAGES.indexOf('learn')
        setCurrentStage('learn')
        setMode('review')
      }, 1800)
      return () => window.clearTimeout(timer)
    }
  }, [completed, running, mode])

  const online = services.filter(s => s.online).length
  const effectiveProfile = (running && live?.attack?.profile) ? live.attack.profile : (profile || 'opportunist')
  const selectedProfileObj = ATTACKER_PROFILES.find((p) => p.id === effectiveProfile) ?? ATTACKER_PROFILES[1]

  // Spine status helper
  function getPillStatus(stageId: Stage): 'ready' | 'active' | 'done' | 'failed' | 'offline' | 'reviewing' {
    if (stageId === 'learn') {
      if (currentStage === 'learn') return 'active'
      return completed ? 'done' : 'offline'
    }
    if (failed && currentStage === stageId) return 'failed'

    // In Review Mode, the stage currently selected to review has 'reviewing' status
    if (mode === 'review' && currentStage === stageId) {
      return 'reviewing'
    }

    if (currentStage === stageId) return 'active'

    const stageIndex = STAGES.indexOf(stageId)

    let hasData = false
    if (stageId === 'attack') {
      hasData = metrics.authEvents.length > 0 || Boolean(metrics.connection)
    } else if (stageId === 'observe') {
      hasData = metrics.commandCount > 0
    } else if (stageId === 'understand') {
      hasData = Boolean(live?.session?.attack_type || (completed && metrics.commandCount > 0))
    } else if (stageId === 'decide') {
      hasData = (live?.actions?.length ?? 0) > 0
    } else if (stageId === 'deceive') {
      hasData = (live?.actions?.length ?? 0) > 0 || bait.length > 0
    } else if (stageId === 'detect') {
      hasData = (live?.rules?.length ?? 0) > 0
    }

    if (hasData || (completed && stageIndex < 6)) return 'done'
    return 'ready'
  }

  const currentIndex = STAGES.indexOf(currentStage)
  const prevStage = currentIndex > 0 ? STAGES[currentIndex - 1] : null
  const nextStage = currentIndex < STAGES.length - 1 ? STAGES[currentIndex + 1] : null

  // User manually selects a stage pill in the spine -> Switch to Review Mode
  const handleSelectSpineStage = (stageId: Stage) => {
    setMode('review')
    setCurrentStage(stageId)
  }

  // Launch fresh contained scenario
  const handleLaunchScenario = () => {
    setMode('live')
    setCurrentStage('attack')
    highestLiveStageIndexRef.current = 0
    if (onRunIntrusion) {
      void onRunIntrusion(effectiveProfile)
    } else {
      onChooseAttacker()
    }
  }

  return (
    <div className={`narrative ${running ? 'narrative-live' : ''}`}>
      {/* ── Persistent Scenario Control Bar ────────────────────────── */}
      <div className="scenario-control-wrapper">
        <div className="scenario-control-ambient"></div>
        <div className="scenario-control-bar" role="toolbar" aria-label="Intrusion scenario execution controls">
        <div className="scenario-control-left">
          <div className="profile-dropdown-control">
            <label htmlFor="attacker-profile-select" className="control-bar-label">
              Attacker Profile
            </label>
            <div className="profile-select-wrapper">
              <select
                id="attacker-profile-select"
                className="profile-select"
                value={effectiveProfile}
                disabled={running || busy}
                onChange={(e) => setProfile?.(e.target.value)}
                aria-label="Select attacker profile"
              >
                {ATTACKER_PROFILES.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </select>
              <ChevronIcon className="profile-select-chevron" />
            </div>
            <div className="profile-desc-pill" title={selectedProfileObj?.detail}>
              <span className="profile-desc-text">
                {selectedProfileObj?.detail ?? profileDesc(effectiveProfile)}
              </span>
            </div>
          </div>
        </div>

        <div className="scenario-control-right">
          {/* Review Mode Banner & Resume Button */}
          {mode === 'review' && running && (
            <div className="review-mode-indicator">
              <span className="review-badge">Reviewing Chapter 0{currentIndex + 1}</span>
              <button
                className="resume-live-btn"
                onClick={() => {
                  setMode('live')
                  setCurrentStage(STAGES[highestLiveStageIndexRef.current])
                }}
                title="Resume automatic live scene tracking"
              >
                <PlayIcon />
                <span>Resume Live</span>
              </button>
            </div>
          )}

          {mode === 'review' && !running && completed && (
            <div className="review-mode-indicator">
              <span className="review-badge completed">Reviewing Scenario Evidence</span>
            </div>
          )}

          <div className="stack-status-badge">
            <span className={`status-dot ${online === (services.length || 6) && online > 0 ? 'online' : ''}`} />
            <span>{online}/{services.length || 6} Stack Online</span>
          </div>

          <div className="scenario-cta-group">
            {running ? (
              <>
                <button className="primary-button cta-running" disabled>
                  <span className="pulsing-live-dot" />
                  <span>Intrusion Running</span>
                </button>
                {onCancel && (
                  <button className="cancel-btn" disabled={busy} onClick={onCancel} title="Stop Scenario">
                    Stop
                  </button>
                )}
              </>
            ) : completed && onRunFollowUp ? (
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <button
                  className="primary-button cta-followup"
                  disabled={busy}
                  onClick={() => {
                    setMode('live')
                    setCurrentStage('attack')
                    highestLiveStageIndexRef.current = 0
                    void onRunFollowUp()
                  }}
                  title="Run attacker again to test the prepared deception environment"
                >
                  <PlayIcon />
                  <span>Run Follow-up Intrusion</span>
                  <ArrowIcon />
                </button>
                <button
                  className="cta-secondary-new"
                  disabled={busy}
                  onClick={handleLaunchScenario}
                  title="Start a new scenario"
                >
                  New Intrusion
                </button>
              </div>
            ) : (
              <button
                className="primary-button cta-launch"
                disabled={busy}
                onClick={handleLaunchScenario}
              >
                <PlayIcon />
                <span>{hasEvidence ? 'Run Intrusion Again' : 'Run Intrusion'}</span>
                <ArrowIcon />
              </button>
            )}
          </div>
        </div>
      </div>
      </div>

      {/* ── Seven-Stage Narrative Spine (Chapter Indicator) ──────── */}
      <nav className="narrative-spine" role="tablist" aria-label="Intrusion narrative spine">
        {STAGES.map((id, i) => {
          const st = getPillStatus(id)
          const sm = stageSummary(id, metrics, live?.session)
          const isCurrent = id === currentStage
          return (
            <button
              key={id}
              role="tab"
              aria-selected={isCurrent}
              className={`spine-pill spine-${st} ${isCurrent ? 'spine-current' : ''}`}
              onClick={() => handleSelectSpineStage(id)}
              title={mode === 'live' ? `Click to inspect Chapter 0${i + 1} in Review Mode` : undefined}
            >
              <span className="spine-idx">0{i + 1}</span>
              <strong>{STAGE_LABELS[id]}</strong>
              {sm && <small className="spine-summary">{sm}</small>}
              {st === 'active' && running && <i className="spine-dot" />}
            </button>
          )
        })}
      </nav>

      {/* ── Active Chapter Scene ──────────────────────────────────── */}
      <div className="narrative-chapter" data-pov={currentStage} role="region" aria-label={`Chapter ${currentIndex + 1}: ${STAGE_LABELS[currentStage]}`}>
        {currentStage === 'attack' && (
          <AttackChapter
            live={live}
            metrics={metrics}
            profile={effectiveProfile}
            online={online}
            total={services.length || 6}
            running={running}
            failed={failed}
            busy={busy}
            onCancel={onCancel}
            onLaunch={handleLaunchScenario}
          />
        )}

        {currentStage === 'observe' && (
          <ObserveChapter
            live={live}
            metrics={metrics}
            running={running}
          />
        )}

        {currentStage === 'understand' && (
          <UnderstandChapter
            live={live}
            metrics={metrics}
          />
        )}

        {currentStage === 'decide' && (
          <DecideChapter
            live={live}
            metrics={metrics}
          />
        )}

        {currentStage === 'deceive' && (
          <DeceiveChapter
            live={live}
            metrics={metrics}
            bait={bait}
          />
        )}

        {currentStage === 'detect' && (
          <DetectChapter
            live={live}
            metrics={metrics}
            onInvestigate={onInvestigate}
          />
        )}

        {currentStage === 'learn' && (
          <LearnChapter
            live={live}
            metrics={metrics}
            onRestart={handleLaunchScenario}
            onRunFollowUp={onRunFollowUp ? () => {
              setMode('live')
              setCurrentStage('attack')
              highestLiveStageIndexRef.current = 0
              void onRunFollowUp()
            } : undefined}
            busy={busy}
          />
        )}

        {/* ── Chapter Footer: Telemetry & Review Controls ────────── */}
        <footer className="chapter-bottom-nav">
          <div className="chapter-nav-buttons">
            {mode === 'review' && prevStage && (
              <button className="secondary-button" onClick={() => setCurrentStage(prevStage)}>
                ← {STAGE_LABELS[prevStage]}
              </button>
            )}
            {mode === 'review' && nextStage && (
              <button className="secondary-button" onClick={() => setCurrentStage(nextStage)}>
                {STAGE_LABELS[nextStage]} →
              </button>
            )}
            {mode === 'live' && running && (
              <span className="live-auto-indicator">
                <span className="live-auto-dot" /> Auto-playing live intrusion story
              </span>
            )}
          </div>

          <div className="chapter-nav-meta">
            <button
              className={`evidence-toggle-btn ${evidenceOpen ? 'active' : ''}`}
              onClick={() => setEvidenceOpen(o => !o)}
            >
              {evidenceOpen ? 'Hide raw evidence' : 'Inspect raw telemetry'} <ArrowIcon />
            </button>
          </div>
        </footer>

        {evidenceOpen && <EvidenceDrawer stage={currentStage} live={live} />}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════
   01. ATTACK Chapter — Authentic Initial Access
   ═══════════════════════════════════════════════════ */

function AttackChapter({
  live, metrics, profile, online, total, running, failed, busy,
  onCancel, onLaunch,
}: {
  live: LiveResponse | null
  metrics: ReturnType<typeof deriveCanonicalMetrics>
  profile: string
  online: number
  total: number
  running: boolean
  failed: boolean
  busy: boolean
  onCancel?: () => void
  onLaunch: () => void
}) {
  const phase = live?.attack?.phase
  const attackProfile = live?.attack?.profile ?? profile
  const { connection, authEvents, hasSuccess, acceptedAuthEvent, failedLogins, acceptedLogins } = metrics

  // Temporal separation: The CURRENT attempt is the hero focus; previous attempts settle into compact history
  const latestAttempt = authEvents[authEvents.length - 1]
  const priorAttempts = authEvents.slice(0, -1)

  const hasEvidence = authEvents.length > 0 || Boolean(connection)
  const isPreparing = !hasEvidence && (phase === 'starting_services' || phase === 'waiting_for_services')
  const isIdleWaiting = !running && !hasEvidence && !failed

  const tensionClass = failedLogins >= 4
    ? 'tension-anticipation-high'
    : failedLogins === 3
      ? 'tension-anticipation-3'
      : failedLogins === 2
        ? 'tension-anticipation-2'
        : failedLogins === 1
          ? 'tension-anticipation-1'
          : ''

  return (
    <div className="chapter-inner">
      <header className="chapter-context">
        <div className="context-strip">
          <span className="chapter-kicker-tag">{STAGE_KICKERS.attack}</span>
          <span className="context-tag"><TerminalIcon />{profileName(attackProfile)}</span>
          <span className="context-tag"><ShieldIcon />Decoy Port 2222</span>
          <span className="context-readiness">
            <i className={`idle-dot ${online === total && total > 0 ? 'online' : ''}`} />
            {online}/{total} stack online
          </span>
        </div>
        <div className="chapter-header-actions">
          {running && onCancel && (
            <button className="cancel-btn" disabled={busy} onClick={onCancel}>Stop scenario</button>
          )}
        </div>
      </header>

      <div className="chapter-body">
        {!hasEvidence && failed ? (
          <div className="chapter-message">
            <h3>The scenario stopped.</h3>
            <p>{live?.attack?.message ?? 'The scenario could not continue. Review captured telemetry below.'}</p>
            <button className="primary-button" onClick={onLaunch} style={{ marginTop: '16px' }}>
              <PlayIcon /> Restart scenario
            </button>
          </div>
        ) : !hasEvidence && isPreparing ? (
          <div className="chapter-message">
            <div className="phase-pulse"><span /><span /><span /></div>
            <h3>Preparing Decoy Environment</h3>
            <p>{live?.attack?.message ?? 'Starting Cowrie honeypot and verifying Elasticsearch indexers.'}</p>
          </div>
        ) : !hasEvidence && isIdleWaiting ? (
          <div className="chapter-message">
            <h3>ShadowMesh Decoy is Ready</h3>
            <p>
              Select an attacker profile above and press <strong>Run Intrusion</strong> to watch a real,
              contained SSH attack unfold on port 2222.
            </p>
            <div className="idle-profile-summary-box">
              <strong>Current Selection: {profileName(attackProfile)}</strong>
              <p>{profileDesc(attackProfile)}</p>
            </div>
            <button className="primary-button" onClick={onLaunch} style={{ marginTop: '16px' }}>
              <PlayIcon /> Run Intrusion <ArrowIcon />
            </button>
          </div>
        ) : (
          <div className={`attack-scene-layout ${tensionClass}`}>
            {/* Top Scene Headline */}
            <div className="chapter-headline">
              <h3>
                {hasSuccess
                  ? 'Access Granted — Shell Established'
                  : connection
                    ? `${profileName(attackProfile)} is Attempting Access`
                    : 'Awaiting Attacker Connection'}
              </h3>
              <p className="chapter-subline">
                {hasSuccess
                  ? `Cowrie accepted the credential for user "${acceptedAuthEvent?.username ?? 'deploy'}" and opened an interactive decoy shell.`
                  : connection
                    ? 'The attacker reached port 2222 and is cycling through credential combinations against Cowrie.'
                    : 'The SSH honeypot is actively listening on port 2222 for incoming probes.'}
              </p>
            </div>

            {/* Alert banner if stopped or failed but evidence was captured */}
            {failed && (
              <div className="scene-connection-banner scene-banner-alert">
                <span className="connection-icon">⚠️</span>
                <div className="connection-text">
                  <strong>Intrusion Stopped</strong>
                  <span>{live?.attack?.message ?? 'Scenario execution was stopped. All telemetry recorded prior to termination is preserved below.'}</span>
                </div>
              </div>
            )}

            {/* Attacker Identity & Live Canonical Tally */}
            <div className="access-dashboard-strip">
              <div className="attacker-card">
                <span className="strip-label">Attacker Identity</span>
                <div className="attacker-identity-row">
                  <span className="attacker-avatar"><TerminalIcon /></span>
                  <div>
                    <strong>{profileName(attackProfile)}</strong>
                    <small>{profileDesc(attackProfile)}</small>
                  </div>
                </div>
              </div>

              <div className="access-tally-card">
                <span className="strip-label">Authentication Tally</span>
                <div className="access-tally-digits">
                  <div className="tally-item tally-fail">
                    <strong>{String(failedLogins).padStart(2, '0')}</strong>
                    <span>Rejected</span>
                  </div>
                  <div className="tally-sep">/</div>
                  <div className={`tally-item ${hasSuccess ? 'tally-ok-active' : 'tally-ok'}`}>
                    <strong>{String(acceptedLogins).padStart(2, '0')}</strong>
                    <span>Accepted</span>
                  </div>
                </div>
              </div>

              <div className="access-target-card">
                <span className="strip-label">Honeypot Sensor</span>
                <div className="target-specs">
                  <strong>Port 2222 / TCP</strong>
                  <small>OpenSSH 8.2p1 Decoy</small>
                </div>
              </div>
            </div>

            {/* Connection Event Banner */}
            {connection && (
              <div className="scene-connection-banner">
                <span className="connection-icon">●</span>
                <div className="connection-text">
                  <strong>SSH Connection Established</strong>
                  <span>{connection.explanation ?? `Attacker opened connection from ${connection.src_ip || '172.18.0.5'} to decoy port 2222.`}</span>
                </div>
                <time className="connection-time">{fmtTime(connection['@timestamp'] ?? connection.timestamp)}</time>
              </div>
            )}

            {/* ── HERO FOCUS: Current Credential Attempt ─────────── */}
            {latestAttempt && (
              <div className="hero-attempt-wrapper">
                <span className="stream-section-title">
                  {hasSuccess ? 'Final Successful Attempt' : `Active Attempt · #${authEvents.length}`}
                </span>
                <div className={`hero-attempt-card ${latestAttempt.event_type === 'cowrie.login.success' ? 'hero-accepted hero-breach' : 'hero-rejected'}`}>
                  <div className="hero-attempt-top">
                    <span className="hero-attempt-tag">
                      Attempt #{String(authEvents.length).padStart(2, '0')}
                    </span>
                    <time className="hero-attempt-time">{fmtTime(latestAttempt['@timestamp'] ?? latestAttempt.timestamp)}</time>
                  </div>

                  <div className="hero-creds-display">
                    <div className="hero-cred-item">
                      <span className="cred-label">Username</span>
                      <strong className="cred-val">{latestAttempt.username || '—'}</strong>
                    </div>
                    <div className="hero-cred-sep">/</div>
                    <div className="hero-cred-item">
                      <span className="cred-label">Password</span>
                      <strong className="cred-val mono-pass">{latestAttempt.password || '••••••'}</strong>
                    </div>
                  </div>

                  <div className="hero-status-row">
                    <span className={`hero-badge ${latestAttempt.event_type === 'cowrie.login.success' ? 'badge-accepted' : 'badge-rejected'}`}>
                      {latestAttempt.event_type === 'cowrie.login.success' ? 'ACCEPTED — VALID CREDENTIAL' : 'REJECTED BY DECOY'}
                    </span>
                    <span className="hero-reason">
                      {latestAttempt.event_type === 'cowrie.login.success'
                        ? 'Matched valid decoy account (deploy:123456) — Cowrie opens interactive decoy shell'
                        : 'Invalid credential pair rejected by Cowrie authentication module'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* ── ACCESS GRANTED Milestone Beat ─────────────────── */}
            {hasSuccess && (
              <div className="access-granted-card" role="status" aria-live="polite">
                <div className="granted-badge-icon">✓</div>
                <div className="granted-body">
                  <span className="granted-eyebrow">Authentication Milestone · Breached</span>
                  <h4 className="granted-title">ACCESS GRANTED — Interactive Shell Established</h4>
                  <p className="granted-desc">
                    The attacker authenticated as <strong>{acceptedAuthEvent?.username ?? 'deploy'}</strong>.
                    Cowrie allocated an isolated PTY shell on <code>novapay-decoy</code> and redirected the intruder to the synthetic filesystem.
                  </p>
                </div>
              </div>
            )}

            {/* ── COMPACT HISTORY: Prior Rejected Attempts ───────── */}
            {priorAttempts.length > 0 && (
              <div className="compact-attempts-pane">
                <span className="compact-attempts-title">
                  Prior Rejected Attempts ({priorAttempts.length})
                </span>
                <div className="compact-attempts-list">
                  {priorAttempts.map((ev, i) => (
                    <div key={`${ev['@timestamp'] ?? i}-${i}`} className="compact-attempt-row">
                      <span className="compact-num">#{String(i + 1).padStart(2, '0')}</span>
                      <span className="compact-user">{ev.username || '—'}</span>
                      <span className="compact-sep">/</span>
                      <span className="compact-pass">{ev.password || '••••••'}</span>
                      <span className="compact-badge-rejected">REJECTED</span>
                      <time className="compact-time">{fmtTime(ev['@timestamp'] ?? ev.timestamp)}</time>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!connection && running && (
              <div className="auth-waiting">
                <div className="phase-pulse"><span /><span /><span /></div>
                <p>Decoy listening on port 2222... waiting for attacker probe.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════
   02. OBSERVE Chapter — Real Decoy Terminal Shell
   ═══════════════════════════════════════════════════ */

function ObserveChapter({
  live, metrics, running,
}: {
  live: LiveResponse | null
  metrics: ReturnType<typeof deriveCanonicalMetrics>
  running: boolean
}) {
  const session = live?.session
  const { commandEvents, commandCount, sensitiveCount, durationSec, hasFollowUp, adaptiveFollowUpCmd } = metrics
  const sessionActive = session?.session_active !== false
  const acceptedUser = metrics.acceptedAuthEvent?.username ?? 'deploy'

  // Temporal separation: The CURRENT command is the hero focus; past commands form compact history
  const latestCmd = commandEvents[commandEvents.length - 1]
  const priorCmds = commandEvents.slice(0, -1)

  const isSensitiveCmd = (cmd: string) => /\/etc\/(passwd|shadow)|\.env|id_rsa/.test(cmd)
  const isFollowUpCmd = (cmd: string) => cmd.includes('grep') && /backupsvc|cloudsync/.test(cmd)
  const isMalwareCmd = (cmd: string) => cmd.includes('wget') || cmd.includes('curl') || cmd.includes('/tmp/')

  const tactical = deriveTacticalPhase(commandEvents)

  return (
    <div className="chapter-inner">
      <header className="chapter-context">
        <div className="context-strip">
          <span className="chapter-kicker-tag">{STAGE_KICKERS.observe}</span>
          <span className="access-origin-anchor">✓ Breached: Port 2222 · {acceptedUser}</span>
          <span className={`tactical-intent-tag ${tactical.isSensitive ? 'tactical-sensitive' : tactical.isFollowUp ? 'tactical-followup' : ''}`}>
            ● {tactical.phaseNumber} · {tactical.phaseName}
          </span>
          {session?.session_id && <span className="context-mono">Session {session.session_id.slice(0, 12)}</span>}
          {session?.attacker_ip && <span className="context-mono">{session.attacker_ip}</span>}
          <span className="context-tag"><TerminalIcon />user: {acceptedUser}</span>
        </div>
        <span className={`context-status ${sessionActive && running ? 'context-live' : ''}`}>
          {sessionActive && running ? '● Shell active' : 'Shell closed'}
        </span>
      </header>

      <div className="chapter-body">
        <div className="chapter-headline">
          <h3>
            {sessionActive && running
              ? 'The Attacker is Exploring the Decoy Shell'
              : 'Decoy Shell Activity Captured'}
          </h3>
          <p className="chapter-subline">
            Every keystroke executed inside Cowrie’s isolated environment is captured in real time.
            Notice how sensitive path queries trigger adaptive bait indicators.
          </p>
        </div>

        {/* ── Two-Session History Comparison (if previous run exists) ── */}
        {live?.previous_run && (
          <TwoSessionCard live={live} metrics={metrics} />
        )}

        {/* ── SPECIAL BEAT: Adaptive Follow-up Highlight ─────── */}
        {hasFollowUp && (
          <div className="adaptive-followup-banner">
            <div className="followup-step-container">
              <div className="followup-step">
                <span className="followup-step-tag">Bait Signal Encountered</span>
                <strong>Synthetic Accounts Detected in Decoy Environment</strong>
                <p>
                  The attacker read <code>/etc/passwd</code> and discovered synthetic accounts (<code>backupsvc</code>, <code>cloudsync</code>) prepared by ShadowMesh.
                </p>
              </div>
              <div className="followup-arrow-divider">↓</div>
              <div className="followup-step followup-action-step">
                <span className="followup-step-tag tag-accent">Targeted Investigation Executed</span>
                <strong>THE PREPARED BAIT WAS INVESTIGATED</strong>
                <p>The simulator issued this follow-up after detecting the configured bait marker in command output:</p>
                <code>$ {adaptiveFollowUpCmd?.command}</code>
              </div>
            </div>
          </div>
        )}

        {/* ── SENSITIVE MOMENT: Truthful Sensitive Path Alert ── */}
        {latestCmd && isSensitiveCmd(latestCmd.command ?? '') && (
          <div className="sensitive-moment-card">
            <span className="sensitive-moment-icon">🍯</span>
            <div className="sensitive-moment-body">
              <strong>Sensitive Path Queried: {latestCmd.command}</strong>
              <p>
                The attacker inspected the decoy credential registry. This behavior is captured and becomes the evidence base for ShadowMesh's adaptive decision.
              </p>
            </div>
          </div>
        )}

        {/* ── HERO COMMAND FOCUS: Emerges from Shell Environment ─── */}
        <div className="terminal-shell-container">
        {latestCmd ? (
          <div className="hero-command-wrapper">
            <span className="stream-section-title">
              {sessionActive && running ? 'Latest Command Executed' : `Final Captured Command · #${commandCount}`}
            </span>
            <div className={`hero-command-card ${commandCount === 1 ? 'hero-cmd-first' : ''} ${isFollowUpCmd(latestCmd.command ?? '') ? 'hero-followup' : isSensitiveCmd(latestCmd.command ?? '') ? 'hero-bait' : ''}`}>
              <div className="hero-cmd-top">
                <span className="hero-prompt-prefix">
                  {acceptedUser}@novapay-decoy:~$
                </span>
                <strong className="hero-cmd-text">{latestCmd.command}</strong>
                <time className="hero-cmd-time">{fmtTime(latestCmd['@timestamp'] ?? latestCmd.timestamp)}</time>
              </div>

              <div className="hero-cmd-interpretation">
                {isFollowUpCmd(latestCmd.command ?? '') ? (
                  <span className="annotation-tag tag-followup">
                    🎯 Adaptive Follow-up: Attacker noticed synthetic accounts staged in /etc/passwd and investigated them
                  </span>
                ) : isSensitiveCmd(latestCmd.command ?? '') ? (
                  <span className="annotation-tag tag-bait">
                    🍯 Sensitive Path Queried: {latestCmd.explanation ?? 'Attacker probed decoy credential registry'}
                  </span>
                ) : isMalwareCmd(latestCmd.command ?? '') ? (
                  <span className="annotation-tag tag-malware">
                    ⚠️ Remote Tool Staging: Attempted external payload download
                  </span>
                ) : (
                  <span className="annotation-tag tag-recon">
                    🔍 {latestCmd.explanation ?? 'Host reconnaissance command'}
                  </span>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="auth-waiting">
            <div className="phase-pulse"><span /><span /><span /></div>
            <p>Decoy shell opened. Awaiting attacker keystrokes...</p>
          </div>
        )}

        {/* ── COMPACT TERMINAL HISTORY PANE ─────────────────── */}
        {priorCmds.length > 0 && (
          <div className="compact-terminal-history">
            <div className="terminal-titlebar">
              <div className="terminal-dots">
                <span className="dot-red" />
                <span className="dot-yellow" />
                <span className="dot-green" />
              </div>
              <span className="terminal-title">
                Prior Shell History ({priorCmds.length} commands)
              </span>
              <span className="terminal-closed-badge">
                {sessionActive && running ? '● RECORDING' : 'ARCHIVED'}
              </span>
            </div>

            <div className="compact-terminal-screen">
              {priorCmds.map((ev, i) => {
                const cmd = ev.command ?? ''
                const isSensitive = isSensitiveCmd(cmd)
                const isFollowUp = isFollowUpCmd(cmd)
                return (
                  <div key={`${ev['@timestamp'] ?? i}-${i}`} className={`compact-term-row ${isFollowUp ? 'row-followup' : isSensitive ? 'row-bait' : ''}`}>
                    <span className="term-prompt">{acceptedUser}@novapay-decoy:~$</span>
                    <span className="term-cmd">{cmd}</span>
                    {isFollowUp ? (
                      <span className="mini-tag tag-followup">Adaptive bait match</span>
                    ) : isSensitive ? (
                      <span className="mini-tag tag-bait">Sensitive path</span>
                    ) : null}
                    <time className="term-time">{fmtTime(ev['@timestamp'] ?? ev.timestamp)}</time>
                  </div>
                )
              })}
            </div>
          </div>
        )}
        </div>

        {/* Canonical Counter Strip */}
        <div className="chapter-counters">
          <div><span>Commands Captured</span><strong>{commandCount}</strong></div>
          <div><span>Sensitive Paths Queried</span><strong>{sensitiveCount}</strong></div>
          <div><span>Session Duration</span><strong>{durationSec ? `${durationSec}s` : '—'}</strong></div>
          <div><span>Decoy Hostname</span><strong>novapay-decoy</strong></div>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════
   03. UNDERSTAND Chapter — Behavioral Synthesis
   ═══════════════════════════════════════════════════ */

function UnderstandChapter({
  live, metrics,
}: {
  live: LiveResponse | null
  metrics: ReturnType<typeof deriveCanonicalMetrics>
}) {
  const session = live?.session
  const { commandEvents, commandCount, sensitiveCount, durationSec, failedLogins, acceptedLogins, totalLogins } = metrics

  const hasActivity = Boolean(session?.session_id || commandCount > 0 || totalLogins > 0)

  // ── Hero 3: Behavioral category grouping from real captured commands ──
  const reconCmds = commandEvents.filter(e => /uname|whoami|id|pwd|hostname/.test(e.command ?? ''))
  const credentialCmds = commandEvents.filter(e => e.phase === 'bait' || /\/etc\/(passwd|shadow)|\.env|id_rsa|grep/.test(e.command ?? ''))
  const payloadCmds = commandEvents.filter(e => /wget|curl|chmod|\/tmp\/|netstat|ps/.test(e.command ?? ''))

  return (
    <div className="chapter-inner">
      <header className="chapter-context">
        <div className="context-strip">
          <span className="chapter-kicker-tag">{STAGE_KICKERS.understand}</span>
          {session?.session_id && <span className="context-mono">{session.session_id.slice(0, 14)}</span>}
          <span className="context-tag"><TerminalIcon />{profileName(session?.attacker_profile || live?.attack?.profile)}</span>
        </div>
      </header>

      <div className="chapter-body">
        <div className="chapter-headline">
          <span className="chapter-kicker-tag" style={{ marginBottom: '6px', display: 'inline-block' }}>WHAT SHADOWMESH OBSERVED</span>
          <h3>{hasActivity ? (failedLogins > 2 ? 'Repeated credential attempts followed by system and credential discovery.' : 'Targeted credential access followed by host reconnaissance.') : 'Awaiting Behavioral Telemetry'}</h3>
          <p className="chapter-subline understand-explain">
            {session?.explanation ??
              (hasActivity
                ? 'ShadowMesh analyzed the real-time event stream from Cowrie, synthesizing brute-force authentication cycles, decoy shell allocation, and command execution into an actionable behavioral profile.'
                : 'Once session activity occurs on the honeypot, ShadowMesh normalizes and synthesizes attacker behavior into an actionable security summary.')}
          </p>
        </div>

        {/* Canonical Behavioral Synthesis Grid — 100% Mathematically Consistent */}
        <div className="understand-grid">
          <div className="understand-fact">
            <span>Login Attempts</span>
            <strong>{totalLogins} ({failedLogins} rejected, {acceptedLogins} accepted)</strong>
          </div>
          <div className="understand-fact">
            <span>Shell Access</span>
            <strong>{acceptedLogins > 0 ? `Granted (${metrics.acceptedAuthEvent?.username ?? 'deploy'})` : 'Rejected'}</strong>
          </div>
          <div className="understand-fact">
            <span>Commands Executed</span>
            <strong>{commandCount} commands</strong>
          </div>
          <div className="understand-fact">
            <span>Sensitive Paths Queried</span>
            <strong>{sensitiveCount} paths probed</strong>
          </div>
          <div className="understand-fact">
            <span>Brute Force Pattern</span>
            <strong>{failedLogins > 3 ? 'Confirmed (>3 attempts)' : 'No'}</strong>
          </div>
          <div className="understand-fact">
            <span>Session Duration</span>
            <strong>{durationSec ? `${durationSec}s` : '—'}</strong>
          </div>
        </div>

        {/* ── Hero 3: Evidence Consolidation Matrix ─────────── */}
        {commandEvents.length > 0 && (
          <div className="evidence-consolidation-grid" role="region" aria-label="Behavioral evidence consolidation">
            <div className={`consolidation-category-card ${reconCmds.length > 0 ? 'category-active' : ''}`}>
              <div className="consolidation-category-header">
                <span className="consolidation-cat-name">01 · System Reconnaissance</span>
                <span className="consolidation-cat-count">{reconCmds.length}</span>
              </div>
              <div className="consolidation-cmd-list">
                {reconCmds.slice(0, 3).map((c, i) => (
                  <code key={i} className="consolidation-cmd-pill">{c.command}</code>
                ))}
                {reconCmds.length === 0 && <small style={{ color: 'var(--muted)', fontSize: '8px' }}>No recon queries</small>}
              </div>
            </div>

            <div className={`consolidation-category-card ${credentialCmds.length > 0 ? 'category-active' : ''}`}>
              <div className="consolidation-category-header">
                <span className="consolidation-cat-name">02 · Credential Discovery</span>
                <span className="consolidation-cat-count">{credentialCmds.length}</span>
              </div>
              <div className="consolidation-cmd-list">
                {credentialCmds.slice(0, 3).map((c, i) => (
                  <code key={i} className="consolidation-cmd-pill" style={{ color: '#b8862d' }}>{c.command}</code>
                ))}
                {credentialCmds.length === 0 && <small style={{ color: 'var(--muted)', fontSize: '8px' }}>No credential queries</small>}
              </div>
            </div>

            <div className={`consolidation-category-card ${payloadCmds.length > 0 ? 'category-active' : ''}`}>
              <div className="consolidation-category-header">
                <span className="consolidation-cat-name">03 · Tool Staging & Execution</span>
                <span className="consolidation-cat-count">{payloadCmds.length}</span>
              </div>
              <div className="consolidation-cmd-list">
                {payloadCmds.slice(0, 3).map((c, i) => (
                  <code key={i} className="consolidation-cmd-pill">{c.command}</code>
                ))}
                {payloadCmds.length === 0 && <small style={{ color: 'var(--muted)', fontSize: '8px' }}>No payload staging</small>}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════
   04. DECIDE Chapter — Adaptive Policy Decision
   ═══════════════════════════════════════════════════ */

function DecideChapter({
  live, metrics,
}: {
  live: LiveResponse | null
  metrics: ReturnType<typeof deriveCanonicalMetrics>
}) {
  const action = metrics.latestAction
  const [paramsOpen, setParamsOpen] = useState(false)

  return (
    <div className="chapter-inner">
      <header className="chapter-context">
        <div className="context-strip">
          <span className="chapter-kicker-tag">{STAGE_KICKERS.decide}</span>
          <span className="context-tag"><ShieldIcon />Recorded Action</span>
          <span className="scope-tag">{action ? scopeText(action) : 'Deterministic Baseline'}</span>
        </div>
      </header>

      <div className="chapter-body">
        <div className="chapter-headline">
          <span className="chapter-kicker-tag" style={{ marginBottom: '6px', display: 'inline-block' }}>RESPONSE SELECTION</span>
          <h3>
            {action
              ? `POLICY DECISION: ${action.name?.replaceAll('_', ' ').toUpperCase() ?? 'SHOW FAKE CREDENTIALS'}`
              : 'Deterministic Baseline Policy'}
          </h3>
          <p className="chapter-subline">
            {action?.explanation ??
              'The deterministic baseline policy evaluates concluded sessions and schedules synthetic credentials or fake files for subsequent sessions.'}
          </p>
        </div>

        {/* ── Story Causality Bridge: Observed -> Decision -> Prepared ── */}
        <div className="decision-consequence-wrapper">
          <div className="two-session-card" style={{ margin: '18px 0', border: '1px solid #d4def0' }}>
            <div className="two-session-header">
              <div>
                <span className="session-col-eyebrow">Adaptive Deception Causality</span>
                <h4>Why This Action Was Selected</h4>
              </div>
              <span className="two-session-badge">Deterministic Policy Evaluation</span>
            </div>
            <div className="two-session-grid">
              <div className="session-col">
                <span className="session-col-eyebrow">01 · What Was Observed</span>
                <strong className="session-col-title">Credential-Related Activity</strong>
                <div className="session-col-details">
                  <div><span>Probed Path:</span> <code>{metrics.sensitiveCount > 0 ? '/etc/passwd' : 'System discovery'}</code></div>
                  <div><span>Behavior Pattern:</span> Attacker inspected available user registries during shell access.</div>
                  <div><span>Heuristic Trigger:</span> Credential reconnaissance detected.</div>
                </div>
              </div>
              <div className="session-col col-primed">
                <span className="session-col-eyebrow">02 · Selected Response</span>
                <strong className="session-col-title">{action?.name ?? 'show_fake_credentials'}</strong>
                <div className="session-col-details">
                  <div><span>Policy Type:</span> Deterministic Baseline</div>
                  <div><span>Activation Scope:</span> <strong>NEXT SESSION</strong></div>
                  <div><span>Intended Preparation:</span> Materialize synthetic service accounts (<code>backupsvc</code>, <code>cloudsync</code>) into Cowrie filesystem.</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {action ? (
          <>
            <div className="decide-record">
              <div className="decide-fact">
                <dt>Decision Policy</dt>
                <dd>{action.policy_name ?? 'Deterministic Baseline'}</dd>
              </div>
              <div className="decide-fact">
                <dt>Target Session ID</dt>
                <dd className="mono-value">{action.session_id ?? '—'}</dd>
              </div>
              <div className="decide-fact">
                <dt>Recorded In Elasticsearch</dt>
                <dd>{fmtTime(action['@timestamp']) || '—'}</dd>
              </div>
              <div className="decide-fact decide-scope">
                <dt>Activation Scope</dt>
                <dd>{scopeText(action)}</dd>
              </div>
            </div>

            {/* Truthful provenance notice */}
            <div className="decide-truthful-callout">
              <strong>Provenance Boundary:</strong>
              <p>
                The baseline policy evaluated the session after it concluded and scheduled bait for <strong>subsequent sessions</strong>.
                The current active container was not altered in-flight. Elasticsearch records the decision intent; the action executor
                materializes files into Cowrie’s honey filesystem.
              </p>
            </div>

            {action.parameters && (
              <div className="decide-params">
                <button className="decide-params-toggle" onClick={() => setParamsOpen(o => !o)}>
                  {paramsOpen ? 'Hide' : 'View'} raw action parameters
                </button>
                {paramsOpen && <pre className="decide-params-json">{JSON.stringify(action.parameters, null, 2)}</pre>}
              </div>
            )}
          </>
        ) : (
          <div className="decide-truthful-callout">
            <strong>Awaiting Decision Record:</strong>
            <p>
              Once the active Cowrie session concludes, the ShadowMesh agent runner evaluates the session summary from <code>honeypot-sessions</code> and writes a deterministic baseline decision to <code>honeypot-rl-actions</code>.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════
   05. DECEIVE Chapter — Honey Filesystem & Bait Cache
   ═══════════════════════════════════════════════════ */

function DeceiveChapter({
  live, metrics, bait,
}: {
  live: LiveResponse | null
  metrics: ReturnType<typeof deriveCanonicalMetrics>
  bait: BaitFile[]
}) {
  const action = metrics.latestAction
  const readyCount = bait.filter(f => f.exists).length
  const [activeTab, setActiveTab] = useState<'passwd' | 'shadow' | 'env' | 'history'>('passwd')
  const [fileContents, setFileContents] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState<boolean>(false)

  const tabToFileId: Record<string, string> = {
    passwd: 'passwd',
    shadow: 'shadow',
    env: '.env',
    history: 'bash_history.txt',
  }

  // Pre-load all bait files from live honeypot filesystem
  useEffect(() => {
    Object.entries(tabToFileId).forEach(([tabKey, fileId]) => {
      api.get<{ content: string }>(`/api/bait/${encodeURIComponent(fileId)}`)
        .then(res => {
          if (res?.content) {
            setFileContents(prev => ({ ...prev, [tabKey]: res.content }))
          }
        })
        .catch(() => {})
    })
  }, [live?.actions?.length])

  // Explicit fetch when active tab is selected if not yet cached
  useEffect(() => {
    const fileId = tabToFileId[activeTab]
    if (!fileId || fileContents[activeTab]) return

    let cancelled = false
    setLoading(true)
    api.get<{ content: string }>(`/api/bait/${encodeURIComponent(fileId)}`)
      .then(res => {
        if (!cancelled && res?.content) {
          setFileContents(prev => ({ ...prev, [activeTab]: res.content }))
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [activeTab, fileContents])

  const samplePasswd = `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\ndeploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n# --- Synthetic Accounts Staged by ShadowMesh --- \nbackupsvc:x:1004:1004:Backup Service:/var/backups:/bin/bash\ncloudsync:x:1005:1005:Cloud Sync:/srv/cloudsync:/bin/bash`
  const sampleShadow = `root:*:19000:0:99999:7:::\ndeploy:$6$V4lid$Z84x01e29uL...:19000:0:99999:7:::\n# --- Synthetic Decoy Hashes Injected ---\nbackupsvc:$6$BkSvc2026$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./abcdefghijk:19700:0:99999:7:7:7\ncloudsync:$6$CldSync2026$mnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./abcdefghijklmnopq:19700:0:99999:7:7:7`
  const sampleEnv = `APP_ENV=production\nDB_HOST=10.10.24.12\nDB_NAME=novapay\nDB_USER=novapay_app\nDB_PASSWORD=N0vaPay-ShadowMesh-2026!\nAWS_ACCESS_KEY_ID=AKIA7NOVAPAYDEMO2026\nAWS_SECRET_ACCESS_KEY=0nlyF4k3ButL00ksRealForShadowMeshDemo2026\nrotation_marker=shadowmesh_live_credentials`
  const sampleHistory = `sudo su -\ncd /srv/novapay\nvim .env\nexport AWS_ACCESS_KEY_ID=AKIA7NOVAPAYDEMO2026\nmysql -h 10.10.24.12 -u novapay_app -pN0vaPay-ShadowMesh-2026!\nhistory -c`

  const activeContent = fileContents[activeTab] || (
    loading ? 'Loading live bait artifact from filesystem...' : (
      activeTab === 'passwd' ? samplePasswd :
      activeTab === 'shadow' ? sampleShadow :
      activeTab === 'env' ? sampleEnv :
      sampleHistory
    )
  )

  return (
    <div className="chapter-inner">
      <header className="chapter-context">
        <div className="context-strip">
          <span className="chapter-kicker-tag">{STAGE_KICKERS.deceive}</span>
          <span className="context-tag"><BaitIcon />Honey Filesystem</span>
          <span className="scope-tag">Next-Session Scope</span>
        </div>
      </header>

      <div className="chapter-body">
        <div className="chapter-headline">
          <span className="chapter-kicker-tag" style={{ marginBottom: '6px', display: 'inline-block' }}>DECEPTION ENVIRONMENT</span>
          <h3>Synthetic Credential & HoneyFS Artifacts</h3>
          <p className="chapter-subline">
            The selected response prepares synthetic credential artifacts for a subsequent session.
            When a follow-up intruder inspects <code>/etc/passwd</code> or environment variables, they encounter these materialized decoys.
          </p>
        </div>

        {/* ── Concrete Deception Filesystem Preview: Spatial Unfolding ── */}
        <div className="deception-unfold-container">
          <div className="deception-filesystem-preview">
            <div className="deception-preview-tabs">
              <button
                className={`deception-preview-tab ${activeTab === 'passwd' ? 'active' : ''}`}
                onClick={() => setActiveTab('passwd')}
              >
                /etc/passwd
              </button>
              <button
                className={`deception-preview-tab ${activeTab === 'shadow' ? 'active' : ''}`}
                onClick={() => setActiveTab('shadow')}
              >
                /etc/shadow
              </button>
              <button
                className={`deception-preview-tab ${activeTab === 'env' ? 'active' : ''}`}
                onClick={() => setActiveTab('env')}
              >
                /opt/novapay/.env
              </button>
              <button
                className={`deception-preview-tab ${activeTab === 'history' ? 'active' : ''}`}
                onClick={() => setActiveTab('history')}
              >
                /root/.bash_history
              </button>
            </div>
            <pre className="deception-preview-body">
              {activeContent}
            </pre>
          </div>
        </div>

        {/* ── Truthful Materialization Status Banner ─────────── */}
        <div className="decide-truthful-callout" style={{ marginTop: '16px' }}>
          <strong>Distinction: Expected from Decision vs Materialized State</strong>
          <p>
            <strong>Expected:</strong> Baseline decision scheduled <code>{action?.name ?? 'show_fake_credentials'}</code> for activation in next session.
            <br />
            <strong>Materialized:</strong> The action executor runs independently and mounts files into <code>/cowrie/honeyfs</code>.
            Subsequent sessions that execute <code>cat /etc/passwd</code> will read the synthetic accounts displayed above.
          </p>
        </div>

        <div className="bait-manifest" style={{ marginTop: '16px' }}>
          {bait.map(f => (
            <div className={`bait-row ${f.exists ? 'bait-ready' : 'bait-missing'}`} key={f.id}>
              <i className={`bait-dot ${f.exists ? 'online' : ''}`} />
              <div className="bait-info">
                <code className="bait-path">{f.attacker_path}</code>
                <span className="bait-desc">{f.explanation}</span>
              </div>
              <span className="bait-status">{f.exists ? `${f.size.toLocaleString()} bytes (Mounted)` : 'Not Materialized'}</span>
            </div>
          ))}
          {bait.length === 0 && <div className="chapter-empty">No bait files configured.</div>}
        </div>

        <div className="chapter-counters">
          <div><span>Materialized Bait Files</span><strong>{readyCount}/{bait.length || 5}</strong></div>
          <div><span>Target Policy Action</span><strong>{action?.name?.replaceAll('_', ' ') ?? 'show fake credentials'}</strong></div>
          <div><span>Mount Destination</span><strong>/cowrie/honeyfs</strong></div>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════
   06. DETECT Chapter — Generated Detection Rules
   ═══════════════════════════════════════════════════ */

function DetectChapter({
  live, metrics, onInvestigate,
}: {
  live: LiveResponse | null
  metrics: ReturnType<typeof deriveCanonicalMetrics>
  onInvestigate: () => void
}) {
  const { totalRules, snortRuleCount, yaraRuleCount, latestRule } = metrics

  return (
    <div className="chapter-inner">
      <header className="chapter-context">
        <div className="context-strip">
          <span className="chapter-kicker-tag">{STAGE_KICKERS.detect}</span>
          <span className="context-tag"><RulesIcon />Generated Rules</span>
          <span className="context-mono">{totalRules} rules</span>
        </div>
      </header>

      <div className="chapter-body">
        <div className="chapter-headline">
          <h3>{totalRules ? `${totalRules} Detection Rules Generated` : 'Waiting for Rule Generator'}</h3>
          <p className="chapter-subline">
            Observed session activity has been compiled into Snort network signatures and YARA filesystem rules.
            These artifacts can be exported to network security monitoring (NSM) sensors to detect similar intrusions.
          </p>
        </div>

        {latestRule && (
          <div className="detect-record">
            <div className="decide-fact">
              <dt>Source Session</dt>
              <dd className="mono-value">{latestRule.session_id ?? '—'}</dd>
            </div>
            <div className="decide-fact">
              <dt>Rule Breakdown</dt>
              <dd>Snort: {snortRuleCount} · YARA: {yaraRuleCount}</dd>
            </div>
            <div className="decide-fact">
              <dt>Generated Timestamp</dt>
              <dd>{fmtTime(latestRule['@timestamp']) || '—'}</dd>
            </div>
            {latestRule.ttps_captured && latestRule.ttps_captured.length > 0 && (
              <div className="decide-fact">
                <dt>Mapped MITRE ATT&CK TTP Patterns</dt>
                <dd className="mono-value">{latestRule.ttps_captured.join(' · ')}</dd>
              </div>
            )}
          </div>
        )}

        {latestRule?.snort_rules && latestRule.snort_rules.length > 0 && (
          <div className="detect-preview">
            <span className="detect-preview-label">Snort Signature Preview</span>
            <pre className="detect-preview-code">{latestRule.snort_rules.join('\n')}</pre>
          </div>
        )}

        {!latestRule && (
          <div className="decide-truthful-callout">
            <strong>Rule Generation Pipeline:</strong>
            <p>
              When a session completes, the rule generation engine evaluates recorded commands and TTP patterns,
              generating Snort network signatures and YARA filesystem indicators in <code>honeypot-generated-rules</code> and <code>rules/output/</code>.
            </p>
          </div>
        )}

        <div className="detect-actions">
          <button className="text-button" onClick={onInvestigate}>Inspect all rules in Investigate view <ArrowIcon /></button>
        </div>
      </div>
    </div>
  )
}

function LearnChapter({
  live, metrics, onRestart, onRunFollowUp, busy,
}: {
  live: LiveResponse | null
  metrics: ReturnType<typeof deriveCanonicalMetrics>
  onRestart: () => void
  onRunFollowUp?: () => void
  busy: boolean
}) {
  return (
    <div className="chapter-inner">
      <header className="chapter-context">
        <div className="context-strip">
          <span className="chapter-kicker-tag">{STAGE_KICKERS.learn}</span>
          <span className="context-tag learn-tag">Offline Evaluation</span>
        </div>
      </header>

      <div className="chapter-body">
        <div className="chapter-headline">
          <span className="chapter-kicker-tag" style={{ marginBottom: '6px', display: 'inline-block' }}>SYSTEM LEARNING & EVALUATION</span>
          <h3>The Intrusion Lifecycle Is Complete</h3>
          <p className="chapter-subline">
            You have followed an authentic intrusion through all seven stages:
            initial probe → authentication → shell activity → understanding → baseline decision → bait caching → rule generation.
          </p>
        </div>

        {/* ── Two-Session History Comparison Card (if previous run exists) ── */}
        {live?.previous_run && (
          <TwoSessionCard live={live} metrics={metrics} />
        )}

        <div className="learn-content">
          <div className="learn-truth-box">
            <strong>System Architecture Integrity:</strong>
            <p>
              The live honeypot utilizes a <strong>deterministic baseline policy</strong> for immediate, safe container deception.
              The PPO reinforcement learning pipeline exists as an <strong>offline evaluation and research suite</strong>,
              allowing researchers to benchmark learned policies against recorded Cowrie session histories.
            </p>
          </div>

          <div className="learn-tools">
            <span className="learn-tools-label">Available Offline Research Tooling</span>
            <code>python agent/train.py --episodes 500</code>
            <code>python agent/evaluate.py --policy baseline</code>
            <code>python agent/compare_policies.py</code>
          </div>

          <div className="learn-restart-action" style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
            {onRunFollowUp && (
              <button
                className="primary-button cta-followup"
                disabled={busy}
                onClick={onRunFollowUp}
              >
                <PlayIcon />Run Follow-up Intrusion (Test Deception)<ArrowIcon />
              </button>
            )}
            <button className="cta-secondary-new" disabled={busy} onClick={onRestart}>
              Start New Scenario
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════
   Evidence Drawer (Progressive Disclosure)
   ═══════════════════════════════════════════════════ */

function EvidenceDrawer({ stage, live }: { stage: Stage; live: LiveResponse | null }) {
  const events = live?.events ?? []
  const session = live?.session
  const action = live?.actions?.at(-1)
  const rules = live?.rules ?? []

  const relevantEvents = (() => {
    switch (stage) {
      case 'attack':
        return events.filter(e => e.event_type === 'cowrie.session.connect' || e.event_type === 'cowrie.login.failed' || e.event_type === 'cowrie.login.success')
      case 'observe':
        return events.filter(e => e.event_type === 'cowrie.command.input')
      default:
        return events
    }
  })()

  const rawDoc = (() => {
    switch (stage) {
      case 'attack':
      case 'observe':
        return relevantEvents
      case 'understand':
        return session ?? null
      case 'decide':
        return action ?? null
      case 'deceive':
        return action?.parameters ?? null
      case 'detect':
        return rules
      case 'learn':
        return null
    }
  })()

  return (
    <div className="evidence-drawer">
      <div className="evidence-section">
        <span className="evidence-label">Raw Telemetry Events ({relevantEvents.length})</span>
        <div className="evidence-events">
          {relevantEvents.map((ev, i) => (
            <div className="evidence-row" key={`${ev['@timestamp'] ?? i}-${i}`}>
              <code className="evidence-type">{ev.event_type}</code>
              <code className="evidence-sid">{ev.session_id ?? ''}</code>
              <time>{fmtTime(ev['@timestamp'] ?? ev.timestamp)}</time>
              {ev.command && <code className="evidence-cmd">{ev.command}</code>}
              {ev.username && <code className="evidence-user">{ev.username}</code>}
            </div>
          ))}
          {relevantEvents.length === 0 && <span className="evidence-empty">No events for this stage.</span>}
        </div>
      </div>

      {rawDoc && (
        <div className="evidence-section">
          <span className="evidence-label">Indexed Document</span>
          <pre className="evidence-raw">{JSON.stringify(rawDoc, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}
