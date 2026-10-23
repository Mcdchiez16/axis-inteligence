import type { Metadata } from 'next';

import { SpfTool } from '@/components/tools/SpfTool';

export const metadata: Metadata = { title: 'SPF Policy Test' };

export default function Page() {
  return <SpfTool />;
}
