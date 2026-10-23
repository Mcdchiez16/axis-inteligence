import type { Metadata } from 'next';

import { BlocklistTool } from '@/components/tools/BlocklistTool';

export const metadata: Metadata = { title: 'Blocklist Lookup' };

export default function Page() {
  return <BlocklistTool />;
}
