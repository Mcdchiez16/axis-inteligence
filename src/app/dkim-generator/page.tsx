import type { Metadata } from 'next';

import { DkimTool } from '@/components/tools/DkimTool';

export const metadata: Metadata = { title: 'DKIM Key Generator' };

export default function Page() {
  return <DkimTool />;
}
