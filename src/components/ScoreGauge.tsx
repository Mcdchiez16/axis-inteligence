/** A half-ring gauge for the 0-100 score, coloured by risk. */
export function ScoreGauge({ score, grade, risk }: { score: number; grade: string; risk: 'low' | 'medium' | 'high' }) {
  const r = 80;
  const c = Math.PI * r;
  const v = Math.max(0, Math.min(100, score)) / 100;
  const color = risk === 'low' ? '#15803d' : risk === 'medium' ? '#d97706' : '#d4041c';
  return (
    <div className="relative mx-auto w-full max-w-[280px]">
      <svg viewBox="0 0 200 116" className="w-full" role="img" aria-label={`Score ${score} out of 100, grade ${grade}`}>
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#ececef" strokeWidth="16" strokeLinecap="round" />
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke={color} strokeWidth="16" strokeLinecap="round" strokeDasharray={`${c * v} ${c}`} style={{ transition: 'stroke-dasharray 900ms cubic-bezier(.2,.8,.2,1)' }} />
      </svg>
      <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
        <span className="text-5xl font-extrabold tabular-nums tracking-tight text-ink">{score}</span>
        <span className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">out of 100</span>
      </div>
    </div>
  );
}

export function Dots({ value }: { value: number }) {
  return (
    <span className="flex gap-1" aria-label={`${value} out of 5`}>
      {[1, 2, 3, 4, 5].map((n) => (
        <span key={n} className={`h-2 w-5 rounded-full ${n <= value ? 'bg-axis-red' : 'bg-line'}`} />
      ))}
    </span>
  );
}
