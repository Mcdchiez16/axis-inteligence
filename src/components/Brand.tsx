import Image from 'next/image';

/** The Axis swoosh with the product name: "Axis" in ink, "Intelligence" in Axis red, as in the company logo. */
export function Brand({ dark = false, size = 'md' }: { dark?: boolean; size?: 'md' | 'lg' }) {
  const h = size === 'lg' ? 40 : 30;
  return (
    <span className="flex items-center gap-2.5">
      <Image src="/axis-mark.png" alt="" width={Math.round((h * 1134) / 426)} height={h} priority />
      <span className={`leading-none tracking-tight ${size === 'lg' ? 'text-2xl' : 'text-lg'} font-extrabold`}>
        <span className={dark ? 'text-white' : 'text-ink'}>Axis</span> <span className="text-axis-red">Intelligence</span>
      </span>
    </span>
  );
}
