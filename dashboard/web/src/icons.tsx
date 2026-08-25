import type { SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement>

const base = (props: IconProps) => ({
  width: 20,
  height: 20,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
  ...props,
})

export const OverviewIcon = (props: IconProps) => <svg {...base(props)}><path d="M4 13h6V4H4zM14 20h6v-9h-6zM4 20h6v-3H4zM14 7h6V4h-6z" /></svg>
export const SessionsIcon = (props: IconProps) => <svg {...base(props)}><path d="M4 5h16M4 12h16M4 19h10" /><circle cx="18" cy="19" r="2" /></svg>
export const BaitIcon = (props: IconProps) => <svg {...base(props)}><path d="M7 3h7l4 4v14H7z" /><path d="M14 3v5h5M10 13h5M10 17h4" /></svg>
export const RulesIcon = (props: IconProps) => <svg {...base(props)}><path d="m5 12 4 4L19 6" /><path d="M5 5h9M5 20h14" /></svg>
export const PlayIcon = (props: IconProps) => <svg {...base(props)}><path d="m8 5 11 7-11 7z" /></svg>
export const ArrowIcon = (props: IconProps) => <svg {...base(props)}><path d="M5 12h14M14 7l5 5-5 5" /></svg>
export const ServerIcon = (props: IconProps) => <svg {...base(props)}><rect x="3" y="4" width="18" height="6" rx="2" /><rect x="3" y="14" width="18" height="6" rx="2" /><path d="M7 7h.01M7 17h.01M11 7h6M11 17h6" /></svg>
export const ShieldIcon = (props: IconProps) => <svg {...base(props)}><path d="M12 3 20 6v5c0 5-3.2 8.4-8 10-4.8-1.6-8-5-8-10V6z" /><path d="m9 12 2 2 4-5" /></svg>
export const TerminalIcon = (props: IconProps) => <svg {...base(props)}><path d="m5 7 4 5-4 5M12 17h7" /></svg>
export const CloseIcon = (props: IconProps) => <svg {...base(props)}><path d="m6 6 12 12M18 6 6 18" /></svg>
export const RefreshIcon = (props: IconProps) => <svg {...base(props)}><path d="M20 7v5h-5M4 17v-5h5" /><path d="M18.2 10A7 7 0 0 0 6 7.8L4 12M6 14a7 7 0 0 0 12 2.2L20 12" /></svg>
export const ExternalIcon = (props: IconProps) => <svg {...base(props)}><path d="M14 4h6v6M20 4l-9 9" /><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6" /></svg>
export const ChevronIcon = (props: IconProps) => <svg {...base(props)}><path d="m9 18 6-6-6-6" /></svg>
export const SettingsIcon = (props: IconProps) => <svg {...base(props)}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H3v-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.6V3h4v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></svg>
