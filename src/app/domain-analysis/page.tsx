import type { Metadata } from 'next';
import { Suspense } from 'react';

import { AnalysisTool } from '@/components/AnalysisTool';

export const metadata: Metadata = { title: 'Domain Analysis' };

export default function Page() {
  return (
    <Suspense>
      <AnalysisTool />
    </Suspense>
  );
}
