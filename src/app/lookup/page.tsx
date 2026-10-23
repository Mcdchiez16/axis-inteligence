import type { Metadata } from 'next';
import { Suspense } from 'react';

import { LookupTool } from '@/components/tools/LookupTool';

export const metadata: Metadata = { title: 'Lookup' };

export default function Page() {
  return (
    <Suspense>
      <LookupTool />
    </Suspense>
  );
}
