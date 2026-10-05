export type Service = {
  id: string
  name: string
  online: boolean
  state: string
}

export type ServicesResponse = {
  services: Service[]
  online: number
  total: number
  elasticsearch: Record<string, unknown> | null
}

export type Session = {
  session_id?: string
  attacker_ip?: string
  service?: string
  session_duration?: number
  login_attempts?: number
  login_success?: boolean
  commands?: string[]
  command_count?: number
  unique_commands?: number
  brute_force_detected?: boolean
  ttp_count?: number
  session_active?: boolean
  session_start?: string
  session_end?: string
  '@timestamp'?: string
  attack_type?: string
  explanation?: string
  attacker_profile?: string
}

export type Event = {
  event_type?: string
  session_id?: string
  command?: string
  explanation?: string
  phase?: 'discovery' | 'credentials' | 'exploration' | 'bait' | 'closed' | 'connection'
  '@timestamp'?: string
  timestamp?: string
  username?: string
  password?: string
  attacker_ip?: string
  src_ip?: string
}

export type Action = {
  name?: string
  action?: string
  action_name?: string
  explanation?: string
  session_id?: string
  '@timestamp'?: string
  policy_name?: string
  action_id?: number
  parameters?: Record<string, string | number | boolean | null>
  reward?: number
  episode?: number
}

export type RuleRecord = {
  session_id?: string
  rule_count?: number
  ttps_captured?: string[]
  snort_rules?: string[]
  yara_rules?: string[]
  '@timestamp'?: string
}

export type Attack = {
  job_id: string
  profile: string
  started_at: string
  status: 'running' | 'completed' | 'failed'
  returncode?: number | null
  phase?: 'starting_services' | 'waiting_for_services' | 'running_attack' | 'processing_events' | 'waiting_for_action' | 'materializing_bait' | 'generating_rules' | 'completed' | 'failed'
  message?: string
  output?: string
  is_follow_up?: boolean
}

export type PreviousRunSummary = {
  job_id: string
  profile: string
  session_id?: string
  session?: Session | null
  action?: Action | null
  is_follow_up?: boolean
  had_bait_trigger?: boolean
  follow_up_occurred?: boolean
  command_count?: number
  completed_at: string
}

export type LiveResponse = {
  attack: Attack | null
  session: Session | null
  events: Event[]
  actions: Action[]
  rules: RuleRecord[]
  previous_run?: PreviousRunSummary | null
  updated_at: string
}

export type BaitFile = {
  id: string
  name: string
  attacker_path: string
  explanation: string
  exists: boolean
  size: number
  metadata?: Record<string, unknown>
}

export type RuleFile = {
  id: string
  name: string
  type: 'Snort' | 'YARA'
  size: number
  modified_at: string
}

export type Job = {
  id: string
  name: string
  status: 'running' | 'completed' | 'failed'
  started_at: string
  finished_at?: string | null
  returncode?: number | null
  output?: string
}

export type AttackerProfile = {
  id: string
  label: string
  index: string
  summary: string
  detail: string
  signal: string
  credentialPlan: string
}

export const ATTACKER_PROFILES: AttackerProfile[] = [
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
