import type { Metadata } from 'next';

import { HeaderTool } from '@/components/tools/HeaderTool';

export const metadata: Metadata = { title: 'Header Analysis' };

export default function Page() {
  return <HeaderTool />;
}
