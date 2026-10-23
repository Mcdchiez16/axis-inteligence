import { Suspense } from 'react';

import { ScoreTool } from '@/components/ScoreTool';

export default function Home() {
  return (
    <Suspense>
      <ScoreTool />
    </Suspense>
  );
}
