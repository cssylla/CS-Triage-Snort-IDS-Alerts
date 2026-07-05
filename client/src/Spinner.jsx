export default function Spinner({ sm = false }) {
  return (
    <span
      className={`inline-block rounded-full border-2 border-slate-600 border-t-sky-400 animate-spin ${sm ? 'w-3.5 h-3.5' : 'w-4 h-4'}`}
      aria-label="Loading"
    />
  )
}
